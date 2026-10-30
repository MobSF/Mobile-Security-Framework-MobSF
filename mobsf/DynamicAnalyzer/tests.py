"""Unit tests for mitmproxy webproxy helpers and HTTP traffic viewer."""
import tempfile
from pathlib import Path
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from mobsf.DynamicAnalyzer.tools import webproxy
from mobsf.DynamicAnalyzer.views.android.dynamic_analyzer import (
    httptools_start,
)


class WebProxyTests(SimpleTestCase):
    """Test flow file validation and traffic viewer endpoints."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.flows_root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_get_flow_file_validates_project_name(self):
        with mock.patch.object(webproxy, 'flows_dir', return_value=self.flows_root):
            valid_flow = self.flows_root / 'com.example.app.flow'
            valid_flow.write_bytes(b'')
            self.assertEqual(
                webproxy.get_flow_file('com.example.app'),
                valid_flow.resolve(),
            )
            self.assertIsNone(webproxy.get_flow_file('../outside'))
            self.assertIsNone(webproxy.get_flow_file(''))

    def test_httptools_json_returns_sorted_flows(self):
        factory = RequestFactory()
        req = factory.get('/httptools', {'project': 'com.example.app', 'json': '1'})
        req.user = mock.MagicMock(is_authenticated=True, is_staff=True)
        with mock.patch.object(webproxy, 'flows_dir', return_value=self.flows_root):
            resp = httptools_start(req)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'"sorted_flows": {}', resp.content)

    def test_parse_fuzzer_proxy_validation(self):
        self.assertEqual(
            webproxy._parse_fuzzer_proxy('http://127.0.0.1:8080'),
            'http://127.0.0.1:8080',
        )
        self.assertEqual(
            webproxy._parse_fuzzer_proxy('https://localhost:8443/'),
            'https://localhost:8443',
        )
        for invalid in (
                '',
                'ftp://127.0.0.1:8080',
                'http://127.0.0.1',
                'http://user:pass@127.0.0.1:8080',
                'http://127.0.0.1:8080/path',
                'http://127.0.0.1:1337',
                'http://bad;host:8080',
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(webproxy._parse_fuzzer_proxy(invalid))

    def test_replay_flows_rejects_invalid_proxy_or_missing_flow(self):
        with mock.patch.object(webproxy, 'flows_dir', return_value=self.flows_root):
            ok, _ = webproxy.replay_flows('com.example.app', 'http://127.0.0.1:8080')
            self.assertFalse(ok)
            valid_flow = self.flows_root / 'com.example.app.flow'
            valid_flow.write_bytes(b'')
            ok, _ = webproxy.replay_flows('com.example.app', 'ftp://127.0.0.1:8080')
            self.assertFalse(ok)
            fake_flow = mock.MagicMock()
            with (mock.patch.object(webproxy, 'load_flows', return_value=[fake_flow]),
                  mock.patch.object(webproxy.threading, 'Thread') as mock_thread):
                ok, msg = webproxy.replay_flows(
                    'com.example.app', 'http://127.0.0.1:8080')
                self.assertTrue(ok)
                self.assertIn('http://127.0.0.1:8080', msg)
                mock_thread.return_value.start.assert_called_once()
