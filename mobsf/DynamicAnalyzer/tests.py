"""Offline regressions for modern Android capability checks."""

import inspect
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory, SimpleTestCase, override_settings

from mobsf.DynamicAnalyzer.views.android.compatibility import (
    full_sdk,
    parse_api,
    release_number,
    runtime_policy,
)
from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.DynamicAnalyzer.views.android.tests_tls import run_tls_tests
from mobsf.DynamicAnalyzer.views.android.tests_common import tls_tests
from mobsf.StaticAnalyzer.tools.androguard4.apk import APK

MODULE = 'mobsf.DynamicAnalyzer.views.android.environment'


@override_settings(ANDROID_MODERN_DYNAMIC=True, ANDROID_ALLOW_LOW_TARGET_INSTALL=False)
class AndroidCompatibilityTests(SimpleTestCase):

    def setUp(self):
        self.env = Environment('emulator-5554')

    def mock_device(self, sdk='36', uid=b'0\n', arch=b'arm64-v8a\n', writable=True):
        def command(args, shell=False, silent=False):
            if args == ['getprop', 'ro.build.version.sdk']:
                return sdk.encode()
            if args == ['getprop', 'ro.product.cpu.abi']:
                return arch
            if args == ['id', '-u']:
                return uid
            if args[:2] == ['test', '-w']:
                return b'' if writable else None
            return b''

        self.env.adb_command = Mock(side_effect=command)

    def test_modern_api_levels_require_explicit_opt_in(self):
        for sdk in ('31', '32', '33', '34', '35', '36', '37'):
            with self.subTest(sdk=sdk):
                self.assertFalse(runtime_policy(sdk)['eligible'])
                result = runtime_policy(sdk, True)
                self.assertTrue(result['eligible'])
                self.assertEqual(result['mode'], 'modern_experimental')
                self.assertFalse(result['automatic_system_ca'])
        self.assertIn('unmapped', runtime_policy('38', True)['release'])

    def test_invalid_sdk_is_rejected(self):
        for sdk in ('', None, 'preview', '36;id', '-1', '1000', '0'):
            with self.subTest(sdk=sdk):
                with self.assertRaises(ValueError):
                    parse_api(sdk)
                self.assertFalse(runtime_policy(sdk, True)['eligible'])

    def test_preview_and_legacy_release_properties(self):
        self.assertEqual(release_number('Baklava', '36'), 16)
        self.assertEqual(release_number('4.4.4', '19'), 4.4)
        self.assertEqual(release_number('12L', '32'), 12)
        self.assertEqual(release_number('17', '37'), 17)
        with self.assertRaises(ValueError):
            release_number('UnknownPreview', '38')

    def test_android17_full_sdk_and_install_floor_diagnostics(self):
        self.mock_device(sdk='37')
        original = self.env.adb_command.side_effect

        def command(args, shell=False, silent=False):
            if args == ['getprop', 'ro.build.version.sdk_full']:
                return b'37.2\n'
            if args == ['getprop', 'ro.build.version.min_supported_target_sdk']:
                return b'28\n'
            return original(args, shell, silent)

        self.env.adb_command.side_effect = command
        result = self.env.runtime_preflight()
        self.assertEqual(result['release'], '17')
        self.assertEqual(result['sdk_full'], '37.2')
        self.assertEqual(result['minimum_supported_target_sdk'], 28)
        self.assertTrue(result['ready'])
        self.assertEqual(full_sdk('37.2;id', 37), '37')
        self.assertEqual(full_sdk('38.2', 37), '37')

    def test_android17_sdk_compiled_apk_uses_the_real_core_decoder(self):
        fixture = Path(__file__).parent / 'fixtures/android17-static.apk'
        parsed = APK(str(fixture))
        self.assertEqual(parsed.get_package(), 'test.mobsf.android17')
        self.assertEqual(parsed.get_min_sdk_version(), '37')
        self.assertEqual(parsed.get_target_sdk_version(), '37')

    def test_read_only_preflight_on_modern_rooted_device(self):
        self.mock_device()
        result = self.env.runtime_preflight()
        self.assertTrue(result['ready'])
        self.assertEqual(result['frida_architecture'], 'arm64')
        for args, _kwargs in self.env.adb_command.call_args_list:
            self.assertIn(args[0][0], ('getprop', 'id', 'test'))

    def test_production_devices_unreachable_devices_and_unknown_abis_fail(self):
        for props in (
            {'uid': b'2000'},
            {'uid': None},
            {'arch': b'riscv64'},
            {'writable': False},
            {'sdk': ''},
        ):
            with self.subTest(props=props):
                self.mock_device(**props)
                self.assertFalse(self.env.runtime_preflight()['ready'])

    def test_modern_system_check_uses_data_and_never_system(self):
        self.mock_device()
        self.assertTrue(self.env.system_check('emulator'))
        self.env.adb_command.assert_any_call(
            ['mkdir', '-p', '/data/local/tmp/mobsf'],
            True,
        )
        self.assertFalse(
            any('/system' in str(call) for call in self.env.adb_command.call_args_list),
        )

    @override_settings(ANDROID_MODERN_DYNAMIC=False)
    def test_disabled_modern_runtime_does_not_write(self):
        self.mock_device()
        self.assertFalse(self.env.system_check('emulator'))
        self.assertEqual(self.env.adb_command.call_count, 1)

    def test_legacy_failed_touch_is_not_reported_ready(self):
        self.mock_device(sdk='30')
        process = Mock(returncode=1)
        process.communicate.return_value = (b'', b'Permission denied')
        with patch(MODULE + '.subprocess.Popen', return_value=process), patch(
            MODULE + '.get_adb',
            return_value='adb',
        ):
            self.assertFalse(self.env.system_check('emulator'))
        self.assertEqual(self.env.agent_directory(), '/system')

    def test_modern_connection_does_not_remount(self):
        self.mock_device()
        with patch.object(
            self.env,
            'run_subprocess_verify_output',
            return_value=True,
        ), patch.object(
            self.env,
            'get_environment',
            return_value='emulator',
        ), patch.object(
            self.env,
            'wait',
        ), patch(
            MODULE + '.get_adb',
            return_value='adb',
        ):
            self.assertTrue(self.env.connect_n_mount())
        self.assertNotIn(
            (['remount'],),
            [call.args for call in self.env.adb_command.call_args_list],
        )

    def test_modern_ca_operations_fail_without_changes(self):
        self.mock_device()
        self.assertFalse(self.env.install_mobsf_ca('install'))
        self.assertFalse(self.env.install_mobsf_ca('remove'))
        self.assertEqual(self.env.adb_command.call_count, 2)
        with self.assertRaises(ValueError):
            self.env.install_mobsf_ca('invalid')

    def test_modern_tls_verdicts_fail_before_device_actions(self):
        self.mock_device()
        with self.assertRaisesMessage(RuntimeError, 'unavailable on modern Android'):
            run_tls_tests(None, 'a' * 32, self.env, 'test.app', 'tls_tests', 1)
        self.assertEqual(self.env.adb_command.call_count, 1)

    def test_blocked_tls_endpoint_does_not_restart_proxy(self):
        self.mock_device()
        request = RequestFactory().post('/tls_tests', {'hash': 'a' * 32})
        module = 'mobsf.DynamicAnalyzer.views.android.tests_common'
        with patch(module + '.Environment', return_value=self.env), patch(
            module + '.get_package_name',
            return_value='test.app',
        ), patch.object(self.env, 'configure_proxy') as proxy:
            result = inspect.unwrap(tls_tests)(request, api=True)
        self.assertEqual(result['status'], 'failed')
        proxy.assert_not_called()

    def test_frida_copy_uses_writable_path_and_matching_version(self):
        self.mock_device()
        with patch(MODULE + '.FridaServerUpdater') as updater:
            updater.return_value.update_frida_server.return_value = True
            self.env.frida_setup()
        pushes = [
            call.args[0]
            for call in self.env.adb_command.call_args_list
            if call.args[0][0] == 'push'
        ]
        self.assertEqual(pushes[0][-1], '/data/local/tmp/mobsf/fd_server')
        self.assertIn('android-arm64', pushes[0][1])

    def test_failed_frida_download_does_not_mark_device_ready(self):
        self.mock_device()
        with patch(MODULE + '.FridaServerUpdater') as updater:
            updater.return_value.update_frida_server.return_value = False
            with self.assertRaises(RuntimeError):
                self.env.frida_setup()
        self.assertFalse(
            any(
                call.args[0][0] == 'push'
                for call in self.env.adb_command.call_args_list
            ),
        )

    def test_frida_marker_and_server_paths_agree(self):
        self.mock_device()
        with patch(
            MODULE + '.subprocess.check_output',
            return_value=self.env.frida_str,
        ), patch(MODULE + '.get_adb', return_value='adb'):
            self.assertTrue(self.env.is_mobsfyied(16))
        self.env.mobsf_agents_setup('frida')
        pushes = [
            call.args[0]
            for call in self.env.adb_command.call_args_list
            if call.args[0][0] == 'push'
        ]
        self.assertEqual(pushes[0][-1], '/data/local/tmp/mobsf/.mobsf-f')
        with patch(MODULE + '.threading.Thread') as thread, patch(
            MODULE + '.subprocess.call',
        ) as execute, patch(MODULE + '.time.sleep'), patch(
            MODULE + '.get_adb',
            return_value='adb',
        ):
            self.env.run_frida_server()
            thread.call_args.kwargs['target']()
        self.assertEqual(
            execute.call_args.args[0][-1],
            '/data/local/tmp/mobsf/fd_server',
        )

    def test_frida_setup_failure_does_not_write_marker(self):
        with patch.object(
            self.env,
            'get_android_version',
            return_value=16,
        ), patch.object(
            self.env,
            'frida_setup',
            side_effect=RuntimeError('Upload failed'),
        ), patch.object(
            self.env,
            'mobsf_agents_setup',
        ) as marker:
            self.assertFalse(self.env.mobsfy_init())
            marker.assert_not_called()

    def test_low_target_install_bypass_is_explicit_and_api_scoped(self):
        self.mock_device()
        with patch.object(self.env, 'is_package_installed', return_value=False):
            self.env.install_apk('/tmp/authorized.apk', 'test.app', '0')
        self.assertFalse(
            any(
                '--bypass-low-target-sdk-block' in str(call)
                for call in self.env.adb_command.call_args_list
            ),
        )
        with override_settings(ANDROID_ALLOW_LOW_TARGET_INSTALL=True), patch.object(
            self.env,
            'is_package_installed',
            return_value=False,
        ):
            self.env.install_apk('/tmp/authorized.apk', 'test.app', '0')
        self.env.adb_command.assert_any_call(
            [
                'install',
                '-r',
                '-t',
                '-d',
                '--bypass-low-target-sdk-block',
                '/tmp/authorized.apk',
            ],
            False,
            True,
        )

    def test_preflight_command_rejects_identifier_and_reports_not_ready(self):
        with patch(MODULE + '.Environment.runtime_preflight') as preflight:
            preflight.return_value = {'ready': False, 'root_adb': False}
            with self.assertRaises(CommandError):
                call_command(
                    'android_preflight',
                    identifier='host;id',
                    stdout=StringIO(),
                )
            preflight.assert_not_called()
            output = StringIO()
            with self.assertRaises(CommandError):
                call_command(
                    'android_preflight',
                    identifier='emulator-5554',
                    as_json=True,
                    stdout=output,
                )
            self.assertIn('"root_adb": false', output.getvalue())

    @override_settings(ANALYZER_IDENTIFIER='emulator-5554')
    def test_preflight_uses_explicit_configured_identifier(self):
        output = StringIO()
        with patch(
            MODULE + '.Environment.runtime_preflight',
            return_value={'ready': True},
        ):
            call_command('android_preflight', as_json=True, stdout=output)
        self.assertIn('"ready": true', output.getvalue())
