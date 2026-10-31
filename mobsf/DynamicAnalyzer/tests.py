"""Unit tests for mitmproxy webproxy helpers and HTTP traffic viewer."""
import tempfile
from pathlib import Path
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from mobsf.DynamicAnalyzer.tools import webproxy
from mobsf.DynamicAnalyzer.views.android.dynamic_analyzer import (
    httptools_start,
)
from mobsf.DynamicAnalyzer.views.android.environment import Environment


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
        self.assertEqual(
            webproxy._parse_fuzzer_proxy('http://[::1]:8080'),
            'http://[::1]:8080',
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


class AndroidFridaServerTests(SimpleTestCase):
    """Test Android emulator Frida server staging and execution."""

    def test_emulator_run_frida_server_stages_to_data_local_tmp(self):
        env = Environment('emulator-5554')
        adb_calls = []

        def fake_adb_command(cmd_list, shell=False, silent=False, timeout=None):
            adb_calls.append((cmd_list, shell))
            if cmd_list == ['pidof', 'fd_server']:
                return b'' if len(adb_calls) == 1 else b'1234\n'
            return b''

        started_cmds = []

        class ImmediateThread:
            def __init__(self, target=None):
                self.target = target
                self.daemon = False

            def start(self):
                if self.target:
                    self.target()

        env_mod = 'mobsf.DynamicAnalyzer.views.android.environment'
        with (mock.patch.object(env, 'get_environment', return_value='emulator'),
              mock.patch.object(env, 'adb_command', side_effect=fake_adb_command),
              mock.patch.object(env, 'stop_frida_server'),
              mock.patch.object(env, 'free_frida_port'),
              mock.patch(f'{env_mod}.get_adb', return_value='adb'),
              mock.patch(f'{env_mod}.threading.Thread', side_effect=ImmediateThread),
              mock.patch(f'{env_mod}.subprocess.call',
                         side_effect=lambda args, **kwargs: started_cmds.append(args)),
              mock.patch(f'{env_mod}.time.sleep')):
            self.assertTrue(env.run_frida_server())

        self.assertIn((['mkdir', '-p', '/data/local/tmp/mobsf'], True), adb_calls)
        self.assertIn(
            (['cp', '/system/fd_server', '/data/local/tmp/mobsf/fd_server'], True),
            adb_calls,
        )
        self.assertIn(
            (['chmod', '755', '/data/local/tmp/mobsf/fd_server'], True),
            adb_calls,
        )
        self.assertEqual(
            started_cmds,
            [['adb', '-s', 'emulator-5554', 'shell',
              '/data/local/tmp/mobsf/fd_server']],
        )
