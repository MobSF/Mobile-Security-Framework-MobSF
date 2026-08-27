"""Unit tests for SSRF-safe network helpers."""
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import patch

from django.test import SimpleTestCase

from mobsf.MobSF.security import (
    _PinnedTLSAdapter,
    is_disallowed_ip,
    resolve_public_ip,
    resolve_public_ips,
    safe_request,
    valid_host,
)


class _RequestHandler(BaseHTTPRequestHandler):
    """Small HTTP endpoint used to prove pinned requests still work."""

    requests = []

    def do_GET(self):  # noqa: N802
        type(self).requests.append((self.path, self.headers.get('Host')))
        if self.path == '/redirect-private':
            self.send_response(302)
            self.send_header('Location', 'http://internal.example/secret')
            self.end_headers()
            return
        if self.path == '/large':
            body = b'x' * 20
        else:
            body = b'{"sha256_cert_fingerprints":[]}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        """Silence HTTP server logs."""


class SSRFHostTests(SimpleTestCase):
    """IP classification and DNS validation."""

    def test_loopback_and_rfc1918_are_disallowed(self):
        self.assertTrue(is_disallowed_ip('127.0.0.1'))
        self.assertTrue(is_disallowed_ip('10.0.0.1'))
        self.assertTrue(is_disallowed_ip('192.168.1.1'))
        self.assertTrue(is_disallowed_ip('172.16.0.1'))
        self.assertTrue(is_disallowed_ip('169.254.169.254'))
        self.assertTrue(is_disallowed_ip('::1'))
        self.assertTrue(is_disallowed_ip('::ffff:127.0.0.1'))
        self.assertTrue(is_disallowed_ip('64:ff9b::7f00:1'))
        self.assertTrue(is_disallowed_ip('2002:7f00:1::'))

    def test_public_ip_is_allowed(self):
        self.assertFalse(is_disallowed_ip('1.1.1.1'))
        self.assertFalse(is_disallowed_ip('8.8.8.8'))

    @patch('mobsf.MobSF.security.socket.getaddrinfo')
    def test_resolve_rejects_when_any_address_is_private(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0)),
        ]
        self.assertIsNone(resolve_public_ip('rebind.example'))
        self.assertFalse(valid_host('rebind.example'))

    @patch('mobsf.MobSF.security.socket.getaddrinfo')
    def test_resolve_returns_public_ip(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 0)),
        ]
        self.assertEqual(resolve_public_ip('example.com'), '1.1.1.1')
        self.assertTrue(valid_host('example.com'))

    @patch('mobsf.MobSF.security.socket.getaddrinfo')
    def test_internal_hostname_is_not_queried(self, mock_gai):
        self.assertIsNone(resolve_public_ip('metadata.google.internal'))
        self.assertIsNone(resolve_public_ip('metadata。google。internal'))
        self.assertIsNone(resolve_public_ip('localhost'))
        self.assertIsNone(resolve_public_ip('intranet'))
        mock_gai.assert_not_called()

    @patch('mobsf.MobSF.security.socket.getaddrinfo')
    def test_resolved_connection_candidates_are_capped(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', (f'8.8.8.{i}', 0))
            for i in range(1, 11)
        ]
        self.assertEqual(len(resolve_public_ips('example.com')), 8)


class SafeRequestTests(SimpleTestCase):
    """Successful requests, rebinding, redirects, proxy, and size limits."""

    def setUp(self):
        _RequestHandler.requests = []
        self.server = HTTPServer(('127.0.0.1', 0), _RequestHandler)
        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _resolver(self, hostname, port):
        if hostname == 'public.example':
            return ('127.0.0.1',)
        return ()

    @patch(
        'mobsf.MobSF.security.resolve_public_ips',
        autospec=True,
    )
    def test_pinned_http_request_succeeds_and_preserves_host(self, resolver):
        resolver.side_effect = self._resolver
        url = f'http://public.example:{self.port}/assetlinks.json'
        with patch.dict(
                'os.environ',
                {'HTTP_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''}):
            response = safe_request(
                'GET',
                url,
                allowed_ports=(self.port,),
                headers={'Host': 'internal.example'},
                timeout=2,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url, url)
        self.assertEqual(
            _RequestHandler.requests,
            [('/assetlinks.json', f'public.example:{self.port}')],
        )

    @patch(
        'mobsf.MobSF.security.resolve_public_ips',
        autospec=True,
    )
    def test_redirect_target_is_independently_rejected(self, resolver):
        resolver.side_effect = self._resolver
        url = f'http://public.example:{self.port}/redirect-private'
        with self.assertRaises(ValueError):
            safe_request(
                'GET',
                url,
                allowed_ports=(80, self.port),
                max_redirects=1,
                timeout=2,
            )
        self.assertEqual(len(_RequestHandler.requests), 1)

    @patch(
        'mobsf.MobSF.security.resolve_public_ips',
        return_value=('127.0.0.1',),
    )
    def test_response_size_is_bounded(self, _resolver):
        url = f'http://public.example:{self.port}/large'
        with self.assertRaises(ValueError):
            safe_request(
                'GET',
                url,
                allowed_ports=(self.port,),
                max_response_size=10,
                timeout=2,
            )

    def test_upstream_proxy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'upstream DNS proxy'):
            safe_request(
                'GET',
                'https://example.com/',
                proxies={'https': 'http://proxy.example:8080'},
            )

    def test_tls_adapter_preserves_sni_and_certificate_hostname(self):
        adapter = _PinnedTLSAdapter('example.com')
        context = adapter.poolmanager.connection_pool_kw
        self.assertEqual(context['server_hostname'], 'example.com')
        self.assertEqual(context['assert_hostname'], 'example.com')
