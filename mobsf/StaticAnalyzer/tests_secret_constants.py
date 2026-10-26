"""Unit tests for known public constants in secret detection."""
from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.common.secret_detection import get_secrets

# Built at runtime so secret scanners do not flag this test file
FAKE_GH_TOKEN = 'ghp' + '_' + 'A1b2C3d4E5' * 3 + 'F6g7H8'
# A high-entropy value reported as a secret today
HIGH_ENTROPY = '5a2a6a42cce67f965cf540fcecf616faca624aa1'
# Strings from the decompiled code of a Flutter release APK
PLUGIN_STRINGS = [
    # flutter_secure_storage: SharedPreferences key name
    'AESVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK',
    'BVGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK',
    'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg',
    # shared_preferences: type prefixes
    'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIGxpc3Qu',
    'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIGxpc3Qu!',
    'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBCaWdJbnRlZ2Vy',
    'VGhpcyBpcyB0aGUgcHJlZml4IGZvciBEb3VibGUu',
]


class SecretConstantsTests(SimpleTestCase):

    def test_plugin_constants_not_reported(self):
        self.assertEqual(get_secrets(PLUGIN_STRINGS), set())

    def test_other_high_entropy_strings_still_reported(self):
        self.assertIn(HIGH_ENTROPY,
                      get_secrets(PLUGIN_STRINGS + [HIGH_ENTROPY]))

    def test_known_format_secrets_still_reported(self):
        self.assertEqual(get_secrets([FAKE_GH_TOKEN]),
                         {f'GitHub token: {FAKE_GH_TOKEN}'})
