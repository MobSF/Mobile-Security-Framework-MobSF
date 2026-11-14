"""Unit tests for iOS Frida dump parsing."""
import json
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.DynamicAnalyzer.views.ios.analysis import ios_api_analysis
from mobsf.DynamicAnalyzer.views.ios.frida_core import (
    Frida,
    parse_dump_message,
)


class _FakeFrida:
    """Minimal stand-in for the Frida instance used by frida_response."""

    screenshot_event = None

    def __init__(self, root):
        self.dump_file = root / 'mobsf_dump_file.txt'
        self.frida_log = root / 'mobsf_frida_out.txt'

    def write_log(self, path, text):
        with open(path, 'a', encoding='utf-8') as flip:
            flip.write(text)


class IOSDumpTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _send(self, fake, payload):
        Frida.frida_response(fake, {'type': 'send', 'payload': payload}, None)

    def test_parse_dump_message_accepts_hook_records(self):
        msg = json.dumps({'[MBSFDUMP] nslog': 'NSLog -> a\nb'})
        self.assertEqual(
            parse_dump_message(msg),
            json.dumps({'nslog': 'NSLog -> a\nb'}))
        self.assertNotIn('\n', parse_dump_message(msg))

    def test_parse_dump_message_rejects_untrusted_text(self):
        for msg in (
                '[Jailbreak Detection Bypass] stat: /Applications/Cydia.app'
                '\n[MBSFDUMP] \n{"<img src=x>":1}',
                '[AUXILIARY] [MBSFDUMP] {"nslog": "x"}',
                '{"nslog": "[MBSFDUMP] x"}',
                '{"[MBSFDUMP] a": 1, "[MBSFDUMP] b": 2}',
                '{"[MBSFDUMP] a": 1',
                '[1, 2]'):
            self.assertIsNone(parse_dump_message(msg), msg)

    def test_marker_injection_does_not_reach_dump_file(self):
        fake = _FakeFrida(self.root)
        path = ('/Applications/Cydia.app\n[MBSFDUMP] \n'
                '{"<img src=x onerror=alert(1)>":1}')
        self._send(
            fake,
            '[Jailbreak Detection Bypass] Hooking native function stat: '
            + path)
        self._send(fake, json.dumps({'[MBSFDUMP] filename': '/tmp/a'}))
        lines = fake.dump_file.read_text().splitlines()
        self.assertEqual(lines, [json.dumps({'filename': '/tmp/a'})])
        self.assertIn('Cydia.app', fake.frida_log.read_text())

    def test_api_analysis_skips_bad_lines(self):
        dump = self.root / 'mobsf_dump_file.txt'
        dump.write_text('\n'.join([
            'not json',
            json.dumps({'nslog': 'hello'}),
            '42',
            json.dumps({'filename': ['unhashable']}),
            json.dumps({'filename': '/var/a'}),
            json.dumps({'network': {'source': 'x'}}),
            json.dumps({'network': {'source': 'y', 'url': 'https://a.b'}}),
        ]) + '\n')
        result = ios_api_analysis(self.root)
        self.assertEqual(result['logs'], ['hello'])
        self.assertEqual(result['files'], ['/var/a'])
        self.assertEqual(
            result['network'], [{'source': 'y', 'url': 'https://a.b'}])
