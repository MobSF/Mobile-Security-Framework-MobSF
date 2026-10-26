"""Unit tests for Swift symbol names in secret detection."""
from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.common.secret_detection import get_secrets

# Built at runtime so secret scanners do not flag this test file
FAKE_GH_TOKEN = 'ghp' + '_' + 'A1b2C3d4E5' * 3 + 'F6g7H8'
# A high-entropy value reported as a secret today
HIGH_ENTROPY = '5a2a6a42cce67f965cf540fcecf616faca624aa1'
# Swift runtime class names and mangled symbols from the binary of a
# Flutter iOS release app (private classes carry a 32 hex discriminator)
SWIFT_SYMBOLS = [
    '_TtC29flutter_secure_storage_darwinP33_662084B2220B6E01EA333F309E6054D8'
    '12BundleFinder',
    '_TtC25webview_flutter_wkwebviewP33_C7EEC6A640D8C4524072DB89CFB81BC6'
    '37WebKitLibraryPigeonInstanceManagerApi',
    '_TtCC25webview_flutter_wkwebview36WebKitLibraryPigeonProxyApiRegistrar'
    'P33_C7EEC6A640D8C4524072DB89CFB81BC635InstanceManagerApiFinalizerDeleg'
    'ate',
    '_TtC25webview_flutter_wkwebview31HTTPURLResponseProxyAPIDelegate',
    '$s29shared_preferences_foundation21LegacyUserDefaultsApiP',
]


class SwiftSymbolSecretsTests(SimpleTestCase):

    def test_swift_symbols_not_reported(self):
        self.assertEqual(get_secrets(SWIFT_SYMBOLS), set())

    def test_other_high_entropy_strings_still_reported(self):
        self.assertIn(HIGH_ENTROPY,
                      get_secrets(SWIFT_SYMBOLS + [HIGH_ENTROPY]))
        # Next to a symbol in the same string
        self.assertIn(HIGH_ENTROPY,
                      get_secrets([f'{SWIFT_SYMBOLS[1]} {HIGH_ENTROPY}']))

    def test_known_format_secret_next_to_symbol_still_reported(self):
        self.assertIn(f'GitHub token: {FAKE_GH_TOKEN}',
                      get_secrets([f'{SWIFT_SYMBOLS[1]} {FAKE_GH_TOKEN}']))
