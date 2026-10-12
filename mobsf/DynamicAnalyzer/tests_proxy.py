"""Offline safety regressions for explicit Burp/Caido capture configuration."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from mobsf.DynamicAnalyzer.tools.capture_runner import (
    capture_arguments,
    capture_config,
    proxy_preflight,
)


@override_settings(
    CAPTURE_PROXY_PROVIDER='burp',
    CAPTURE_PROXY_URL='http://127.0.0.1:8080',
    CAPTURE_PROXY_CA_FILE='',
    PROXY_IP='127.0.0.1',
    PROXY_PORT=1337,
)
class CaptureProxyTests(SimpleTestCase):

    def test_strict_tls_chain_and_local_bind(self):
        with tempfile.TemporaryDirectory() as home:
            with override_settings(MOBSF_HOME=home):
                args = capture_arguments(1337, 'test.mobsf.fixture')
        self.assertEqual(args[args.index('--listen-host') + 1], '127.0.0.1')
        self.assertIn('upstream:http://127.0.0.1:8080', args)
        self.assertNotIn('-k', args)
        self.assertNotIn('ssl_insecure=true', args)

    def test_rejects_credentials_paths_dns_and_capture_loops(self):
        for url in (
            'http://user:password@127.0.0.1:8080',
            'https://127.0.0.1:8080',
            'http://127.0.0.1:1337',
            'http://127.0.0.1:8080/path',
            'http://localhost:8080',
            'http://127.0.0.1:99999',
            'http://127.0.0.1:8080?x=y',
        ):
            with self.subTest(url=url), override_settings(CAPTURE_PROXY_URL=url):
                with self.assertRaises(ValueError):
                    capture_config()
        with override_settings(CAPTURE_PROXY_PROVIDER='unknown'):
            with self.assertRaises(ValueError):
                capture_config()

    def test_malformed_ca_fails_instead_of_disabling_verification(self):
        with tempfile.TemporaryDirectory() as home:
            ca = Path(home) / 'ca.pem'
            ca.write_text('invalid certificate')
            with override_settings(CAPTURE_PROXY_CA_FILE=str(ca)):
                with self.assertRaises(OSError):
                    capture_config()

    def test_preflight_only_connects_to_explicit_proxy_listener(self):
        with patch(
            'mobsf.DynamicAnalyzer.tools.capture_runner.socket.create_connection',
        ) as connection:
            result = proxy_preflight()
        connection.assert_called_once_with(('127.0.0.1', 8080), timeout=3)
        self.assertTrue(result['ready'])
        self.assertTrue(result['tls_verification'])
        with patch(
            'mobsf.DynamicAnalyzer.tools.capture_runner.socket.create_connection',
            side_effect=OSError,
        ):
            self.assertFalse(proxy_preflight()['ready'])

    def test_project_cannot_escape_flow_directory(self):
        for project in ('../escape', '/absolute', 'foo;command', '..', ''):
            with self.subTest(project=project), self.assertRaises(ValueError):
                capture_arguments(1337, project)
