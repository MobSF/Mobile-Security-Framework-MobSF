"""Unit tests for Frida API monitor parsing, formatting and views."""
import json
import tempfile
from pathlib import Path
from unittest import mock

from django.test import RequestFactory, SimpleTestCase, override_settings

from mobsf.DynamicAnalyzer.views.android import (
    api_monitor,
    frida_core,
    tests_frida,
)

CHECKSUM = '4b44e6d39d806949a092e47c4028276c'


def js_event(**overrides):
    event = {
        'name': 'Crypto - Hash',
        'class': 'java.security.MessageDigest',
        'method': 'digest',
        'argumentTypes': ['[B'],
        'arguments': [{'$t': 'bytes', 'len': 5, 'hex': '68656c6c6f'}],
        'returnValue': {'$t': 'bytes', 'len': 2, 'hex': '00ff'},
        'calledFrom': 'com.example.App.hash(App.java:10)',
        'stack': ['java.security.MessageDigest.digest(MessageDigest.java:1)',
                  'com.example.App.hash(App.java:10)'],
        'thread': 'main',
        'timestamp': 1700000000000,
    }
    event.update(overrides)
    return event


class ApiMonitorFormatTests(SimpleTestCase):
    """Formatting of structured values sent by api_monitor.js."""

    def test_bytes_render_as_text_or_hex(self):
        self.assertEqual(
            api_monitor.format_value({'$t': 'bytes', 'len': 5, 'hex': '68656c6c6f'}),
            'byte[5] "hello"')
        self.assertEqual(
            api_monitor.format_value({'$t': 'bytes', 'len': 2, 'hex': '00ff'}),
            'byte[2] 0x00ff')
        self.assertEqual(
            api_monitor.format_value({'$t': 'bytes', 'len': 9, 'hex': '6869'}),
            'byte[9] "hi"…')

    def test_invalid_hex_is_ignored(self):
        self.assertEqual(
            api_monitor.format_value({'$t': 'bytes', 'len': 1, 'hex': 'zz'}),
            'byte[1] 0x…')

    def test_scalars_objects_and_lists(self):
        self.assertEqual(api_monitor.format_value(None), 'null')
        self.assertEqual(api_monitor.format_value(True), 'true')
        self.assertEqual(api_monitor.format_value(577), '577')
        self.assertEqual(api_monitor.format_value('a\nb'), '"a\\nb"')
        self.assertEqual(
            api_monitor.format_value({
                '$t': 'object',
                'cls': 'android.content.Intent',
                'str': 'Intent { act=android.intent.action.VIEW }'}),
            'Intent { act=android.intent.action.VIEW }')
        self.assertEqual(
            api_monitor.format_value({'$t': 'object', 'cls': 'a.B', 'str': None}),
            'a.B')
        self.assertEqual(
            api_monitor.format_value(['_id', {'$t': 'more', 'count': 3}]),
            '["_id", … 3 more]')
        self.assertEqual(api_monitor.format_value({'unexpected': 1}), 'object')

    def test_values_are_bounded(self):
        out = api_monitor.format_value('x' * 10000)
        self.assertLessEqual(len(out), api_monitor.MAX_TEXT + 1)
        nested = [[[[['deep']]]]]
        self.assertIn('[…]', api_monitor.format_value(nested))

    def test_java_type_names(self):
        self.assertEqual(api_monitor.java_type_name('[B'), 'byte[]')
        self.assertEqual(
            api_monitor.java_type_name('[Ljava.lang.String;'), 'String[]')
        self.assertEqual(api_monitor.java_type_name('java.lang.String'), 'String')
        self.assertEqual(api_monitor.java_type_name('int'), 'int')


class ApiMonitorEventTests(SimpleTestCase):
    """Validation and serialization of hook events."""

    def test_normalize_event(self):
        entry = api_monitor.normalize_event(js_event())
        self.assertEqual(entry['api'], 'MessageDigest.digest')
        self.assertEqual(entry['signature'], 'digest(byte[])')
        self.assertEqual(entry['arguments'], ['byte[5] "hello"'])
        self.assertEqual(entry['returnValue'], 'byte[2] 0x00ff')
        self.assertEqual(entry['result'], entry['returnValue'])
        self.assertEqual(entry['thread'], 'main')
        self.assertEqual(len(entry['stack']), 2)

    def test_void_and_exception(self):
        event = js_event(exception='java.io.FileNotFoundException: x')
        del event['returnValue']
        entry = api_monitor.normalize_event(event)
        self.assertIsNone(entry['returnValue'])
        self.assertEqual(entry['exception'], 'java.io.FileNotFoundException: x')

    def test_base64_decoded_text(self):
        entry = api_monitor.normalize_event(js_event(
            name='Base64',
            **{'class': 'android.util.Base64'},
            method='decode',
            argumentTypes=['java.lang.String', 'int'],
            arguments=['aGVsbG8=', 0],
            returnValue={'$t': 'bytes', 'len': 5, 'hex': '68656c6c6f'}))
        self.assertEqual(entry['decoded'], 'hello')

    def test_rejects_malformed_events(self):
        for payload in ('not json', '[]', '{"class": "a"}',
                        json.dumps(js_event(method=5)), None):
            self.assertIsNone(api_monitor.serialize_event(payload))

    def test_untrusted_types_are_coerced(self):
        entry = api_monitor.normalize_event(js_event(
            name=['x'], thread={'a': 1}, timestamp='now',
            stack='not-a-list', calledFrom=7))
        self.assertEqual(entry['name'], 'Other')
        self.assertEqual(entry['thread'], '')
        self.assertIsNone(entry['timestamp'])
        self.assertEqual(entry['stack'], [])
        self.assertEqual(entry['calledFrom'], '')

    def test_app_instance_and_count(self):
        entry = api_monitor.normalize_event(js_event(
            app=False, instance='MD5', count=7))
        self.assertFalse(entry['app'])
        self.assertEqual(entry['instance'], 'MD5')
        self.assertEqual(entry['count'], 7)
        entry = api_monitor.normalize_event(js_event(
            app='yes', instance=['x'], count=-3))
        self.assertTrue(entry['app'])
        self.assertIsNone(entry['instance'])
        self.assertEqual(entry['count'], 1)
        entry = api_monitor.normalize_event(js_event(count=10 ** 12))
        self.assertEqual(entry['count'], api_monitor.MAX_COUNT)

    def test_java_util_base64(self):
        entry = api_monitor.normalize_event(js_event(
            name='Base64',
            **{'class': 'java.util.Base64$Encoder'},
            method='encodeToString',
            argumentTypes=['[B'],
            arguments=[{'$t': 'bytes', 'len': 2, 'hex': '6869'}],
            returnValue='aGk='))
        self.assertEqual(entry['decoded'], 'hi')

    def test_batch_payload(self):
        payload = json.dumps({'events': [
            js_event(), 'junk', js_event(method='update')]})
        lines = api_monitor.serialize_event(payload).splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['method'], 'update')
        self.assertIsNone(api_monitor.serialize_event('{"events": "x"}'))
        many = json.dumps({'events': [js_event()] * 500})
        self.assertEqual(
            len(api_monitor.serialize_event(many).splitlines()),
            api_monitor.MAX_BATCH)

    def test_serialized_event_is_single_line(self):
        line = api_monitor.serialize_event(json.dumps(js_event(
            arguments=['line1\nline2\r\u2028'])))
        self.assertTrue(line.endswith('\n'))
        self.assertEqual(line.count('\n'), 1)


class ApiMonitorReadTests(SimpleTestCase):
    """Reading stored logs in current and legacy formats."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'mobsf_api_monitor.txt'

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip_skips_bad_lines(self):
        good = api_monitor.serialize_event(json.dumps(js_event()))
        self.path.write_text(good + '{broken\n' + good, 'utf-8')
        entries = api_monitor.read_api_monitor(self.path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]['arguments'], ['byte[5] "hello"'])
        self.assertEqual(entries[0]['signature'], 'digest(byte[])')

    def test_legacy_format(self):
        legacy = [{
            'name': 'Crypto - Hash',
            'class': 'java.security.MessageDigest',
            'method': 'update',
            'arguments': [[104, 105]],
            'calledFrom': 'java.security.MessageDigest.digest(x)',
        }, {
            'name': 'Crypto - Hash',
            'class': 'java.security.MessageDigest',
            'method': 'digest',
            'arguments': [],
            'result': '70,-1',
            'returnValue': '70-1',
            'calledFrom': 'x',
        }, {
            'name': 'IPC',
            'class': 'android.content.ContextWrapper',
            'method': 'registerReceiver',
            'arguments': ['<instance: android.content.IntentFilter>', None],
            'calledFrom': 'x',
        }]
        self.path.write_text(
            ''.join(json.dumps(e) + ',' for e in legacy), 'utf-8')
        entries = api_monitor.read_api_monitor(self.path)
        self.assertEqual(entries[0]['arguments'], ['byte[2] "hi"'])
        self.assertEqual(entries[1]['returnValue'], 'byte[2] 0x46ff')
        self.assertEqual(
            entries[2]['arguments'],
            ['<instance: android.content.IntentFilter>', 'null'])

    def test_missing_file(self):
        self.assertEqual(api_monitor.read_api_monitor(self.path), [])

    def test_stored_fields_round_trip(self):
        line = api_monitor.serialize_event(json.dumps(js_event(
            app=False, instance='SHA-256', count=4)))
        self.path.write_text(line, 'utf-8')
        entry = api_monitor.read_api_monitor(self.path)[0]
        self.assertFalse(entry['app'])
        self.assertEqual(entry['instance'], 'SHA-256')
        self.assertEqual(entry['count'], 4)

    def test_legacy_entries_count_as_app_calls(self):
        self.path.write_text(json.dumps({
            'name': 'IPC', 'class': 'a.B', 'method': 'c',
            'arguments': [], 'calledFrom': 'x'}) + ',', 'utf-8')
        entry = api_monitor.read_api_monitor(self.path)[0]
        self.assertTrue(entry['app'])
        self.assertEqual(entry['count'], 1)

    def test_group_collapses_duplicates(self):
        entry = api_monitor.normalize_event(js_event(count=3))
        other = api_monitor.normalize_event(js_event(calledFrom='b.C.d(C.java:1)'))
        groups, strings = api_monitor.group_api_calls([entry, entry, other])
        calls = groups['Crypto - Hash']
        self.assertEqual([c['count'] for c in calls], [6, 1])
        self.assertEqual(calls[0]['icon'], 'fas fa-hashtag')
        self.assertEqual(strings, [])

    def test_group_orders_app_calls_first(self):
        framework = api_monitor.normalize_event(js_event(app=False))
        app = api_monitor.normalize_event(js_event(instance='MD5'))
        groups, _ = api_monitor.group_api_calls([framework, app])
        self.assertEqual(
            [c['app'] for c in groups['Crypto - Hash']], [True, False])
        self.assertEqual(
            api_monitor.framework_call_counts(groups), {'Crypto - Hash': 1})


class LiveApiViewTests(SimpleTestCase):
    """Live API monitor view."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.upload_dir = Path(self.tmp.name)
        app_dir = self.upload_dir / CHECKSUM
        app_dir.mkdir()
        line = api_monitor.serialize_event(json.dumps(js_event()))
        (app_dir / 'mobsf_api_monitor.txt').write_text(line * 3, 'utf-8')
        self.factory = RequestFactory()
        self.settings_override = override_settings(UPLD_DIR=self.tmp.name)
        self.settings_override.enable()

    def tearDown(self):
        self.settings_override.disable()
        self.tmp.cleanup()

    def _call(self, request, api=False):
        request.user = mock.MagicMock(is_authenticated=True, is_staff=True)
        return tests_frida.live_api(request, api)

    def _post(self, data):
        req = self.factory.post('/live_api/', data)
        req._dont_enforce_csrf_checks = True
        return json.loads(self._call(req).content)

    def test_incremental_fetch(self):
        capture = self._post({'hash': CHECKSUM, 'offset': '0'})['capture']
        data = self._post({'hash': CHECKSUM, 'offset': '1', 'capture': capture})
        self.assertEqual(data['total'], 3)
        self.assertEqual(data['offset'], 1)
        self.assertEqual(len(data['data']), 2)
        self.assertFalse(data['reset'])

    def test_restarted_capture_resets(self):
        capture = self._post({'hash': CHECKSUM, 'offset': '0'})['capture']
        log = self.upload_dir / CHECKSUM / 'mobsf_api_monitor.txt'
        log.unlink()
        event = js_event()
        event['timestamp'] += 1
        log.write_text(
            api_monitor.serialize_event(json.dumps(event)) * 5, 'utf-8')
        data = self._post({'hash': CHECKSUM, 'offset': '3', 'capture': capture})
        self.assertTrue(data['reset'])
        self.assertEqual(data['offset'], 0)
        self.assertEqual(len(data['data']), 5)
        self.assertNotEqual(data['capture'], capture)

    def test_offset_past_end_resets(self):
        data = self._post({'hash': CHECKSUM, 'offset': '99'})
        self.assertTrue(data['reset'])
        self.assertEqual(len(data['data']), 3)

    def test_bad_offset_defaults_to_start(self):
        data = self._post({'hash': CHECKSUM, 'offset': '-5'})
        self.assertEqual(len(data['data']), 3)

    def test_invalid_hash(self):
        data = self._post({'hash': '../etc', 'offset': '0'})
        self.assertEqual(data['status'], 'failed')

    def test_rest_api_returns_all_entries(self):
        req = self.factory.post('/api/v1/frida/api_monitor', {'hash': CHECKSUM})
        data = self._call(req, api=True)
        self.assertEqual(len(data['data']), 3)

    def test_get_requires_valid_package(self):
        req = self.factory.get('/live_api/', {'hash': CHECKSUM, 'package': '$(id)'})
        data = json.loads(self._call(req).content)
        self.assertEqual(data['status'], 'failed')


class FridaIntegrationTests(SimpleTestCase):
    """API monitor wiring in the Frida session code."""

    def test_api_monitor_loads_last(self):
        with tempfile.TemporaryDirectory() as tmp:
            default = Path(tmp) / 'default'
            default.mkdir()
            for name in ('api_monitor', 'root_bypass', 'ssl_pinning_bypass'):
                (default / f'{name}.js').write_text(f'// {name}', 'utf-8')
            fake = mock.Mock(frida_dir=Path(tmp))
            scripts = frida_core.Frida.get_scripts(fake, 'default', ['*'])
        self.assertEqual(scripts[-1], '// api_monitor')

    def test_flush_active_calls_every_script(self):
        flushed, other = mock.Mock(), mock.Mock()
        other.exports_sync.flush_api_monitor.side_effect = Exception('no rpc')
        key = (CHECKSUM, 'emulator-5554')
        entry = {'scripts': [other, flushed]}
        with mock.patch.dict(frida_core._ACTIVE_SESSIONS, {key: entry}):
            frida_core.Frida.flush_active(*key)
        flushed.exports_sync.flush_api_monitor.assert_called_once_with()
