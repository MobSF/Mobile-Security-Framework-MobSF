"""Unit tests for source ZIP type detection."""
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android.apk import valid_source_code

CHECKSUM = 'f1a7f1a7f1a7f1a7f1a7f1a7f1a7f1a7'
MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/'
            'android" package="com.example.app"/>')
# Layout of a project created with flutter create
FLUTTER_PROJECT = {
    'pubspec.yaml': 'name: demo\n',
    '.gitignore': 'flutter-ignore\n',
    'lib/main.dart': 'void main() {}\n',
    'android/.gitignore': 'android-ignore\n',
    'android/build.gradle.kts': '',
    'android/app/src/main/AndroidManifest.xml': MANIFEST,
    'android/app/src/main/kotlin/com/example/MainActivity.kt': '',
    'ios/Runner/Info.plist': '',
}
STUDIO_PROJECT = {
    '.gitignore': 'studio-ignore\n',
    'app/src/main/AndroidManifest.xml': MANIFEST,
    'app/src/main/java/com/example/MainActivity.java': '',
}


class SourceZipTypeTests(SimpleTestCase):

    def _tree(self, base, files):
        for rel, data in files.items():
            path = Path(base) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)

    def _check(self, app_dir):
        with mock.patch(
                'mobsf.StaticAnalyzer.views.android.apk.append_scan_status'):
            return valid_source_code(CHECKSUM, app_dir)

    def test_flutter_project_at_zip_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, FLUTTER_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))
            root = Path(tmp)
            self.assertTrue(
                (root / 'app/src/main/AndroidManifest.xml').is_file())
            # Files already at the root are kept, not overwritten
            self.assertEqual((root / '.gitignore').read_text(),
                             'flutter-ignore\n')
            self.assertTrue((root / 'lib/main.dart').is_file())

    def test_flutter_project_wrapped_in_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(Path(tmp) / 'demo', FLUTTER_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))
            self.assertTrue(
                (Path(tmp) / 'app/src/main/AndroidManifest.xml').is_file())

    def test_studio_project_at_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, STUDIO_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))

    def test_studio_project_one_level_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(Path(tmp) / 'MyApp', STUDIO_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))
            self.assertTrue(
                (Path(tmp) / 'app/src/main/AndroidManifest.xml').is_file())
            self.assertEqual((Path(tmp) / '.gitignore').read_text(),
                             'studio-ignore\n')

    def test_unsupported_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'README.md': 'x'})
            self.assertEqual(self._check(tmp), ('', False))
