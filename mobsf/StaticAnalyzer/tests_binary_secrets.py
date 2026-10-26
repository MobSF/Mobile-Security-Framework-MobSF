"""Unit tests for secret detection in native binaries."""
from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android.strings import strings_from_so
from mobsf.StaticAnalyzer.views.common.secret_detection import (
    get_binary_secrets,
)

# Built at runtime so secret scanners do not flag this test file
FAKE_GH_TOKEN = 'ghp' + '_' + 'A1b2C3d4E5' * 3 + 'F6g7H8'
# Reported today as secrets from libflutter.so / Flutter.framework
ENGINE_NOISE = [
    '0123456789abcdefABCDEF',
    '5a2a6a42cce67f965cf540fcecf616faca624aa1',
]
SNAPSHOT_HASH = 'ace654289f5abc240509fc941453ebc5'
SNAPSHOT_HEADER = (f'{SNAPSHOT_HASH}product no-code_comments '
                   'no-dwarf_stack_traces_mode dedup_instructions arm64 '
                   'android compressed-pointers')


class BinarySecretsTests(SimpleTestCase):

    def test_android_engine_reports_known_formats_only(self):
        res = get_binary_secrets('lib/arm64-v8a/libflutter.so',
                                 ENGINE_NOISE + [FAKE_GH_TOKEN])
        self.assertEqual(res, {f'GitHub token: {FAKE_GH_TOKEN}'})

    def test_ios_engine_reports_known_formats_only(self):
        res = get_binary_secrets(
            'Payload/Runner.app/Frameworks/Flutter.framework/Flutter',
            ENGINE_NOISE)
        self.assertEqual(res, set())

    def test_other_libraries_unchanged(self):
        res = get_binary_secrets('lib/arm64-v8a/libfoo.so', ENGINE_NOISE)
        self.assertTrue(set(ENGINE_NOISE) & res)

    def test_dart_snapshot_hash_dropped(self):
        # A 32 hex string elsewhere in the snapshot is still reported
        other = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'
        res = get_binary_secrets('lib/arm64-v8a/libapp.so',
                                 [SNAPSHOT_HEADER, other])
        self.assertNotIn(SNAPSHOT_HASH, res)
        self.assertIn(other, res)

    def test_strings_from_so_uses_it(self):
        sos = strings_from_so('f1a7f1a7f1a7f1a7f1a7f1a7f1a7f1a7', [
            {'lib/arm64-v8a/libflutter.so': ENGINE_NOISE},
            {'lib/arm64-v8a/libapp.so': [SNAPSHOT_HEADER]},
        ])
        secrets = {s for so in sos for v in so.values() for s in v['secrets']}
        self.assertEqual(secrets, set())
