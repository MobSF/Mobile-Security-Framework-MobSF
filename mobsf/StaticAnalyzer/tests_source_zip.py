"""Unit tests for source ZIP type detection and post-scan views."""
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from mobsf.MobSF.init import api_key
from mobsf.MobSF.utils import get_android_src_dir
from mobsf.StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.android.apk import valid_source_code
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest_file,
)
from mobsf.StaticAnalyzer.views.android.network_security import (
    read_netsec_config,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    android_source_root,
)

CHECKSUM = 'f1a7f1a7f1a7f1a7f1a7f1a7f1a7f1a7'
MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/'
            'android" package="com.example.app"/>')
MAIN = 'class MainActivity\n'
# Layout of a project created with flutter create
FLUTTER_PROJECT = {
    'pubspec.yaml': 'name: demo\n',
    '.gitignore': 'flutter-ignore\n',
    'lib/main.dart': 'void main() {}\n',
    'android/.gitignore': 'android-ignore\n',
    'android/build.gradle.kts': '',
    'android/app/src/main/AndroidManifest.xml': MANIFEST,
    'android/app/src/main/kotlin/com/example/MainActivity.kt': MAIN,
    'android/app/src/main/res/xml/netsec.xml': '<network-security-config/>',
    'ios/Runner/Info.plist': '',
}
STUDIO_PROJECT = {
    '.gitignore': 'studio-ignore\n',
    'app/src/main/AndroidManifest.xml': MANIFEST,
    'app/src/main/java/com/example/MainActivity.java': MAIN,
}


def make_tree(base, files):
    for rel, data in files.items():
        path = Path(base) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)


class SourceZipTypeTests(SimpleTestCase):

    def _check(self, app_dir):
        with mock.patch(
                'mobsf.StaticAnalyzer.views.android.apk.append_scan_status'):
            return valid_source_code(CHECKSUM, app_dir)

    def test_flutter_project_at_zip_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, FLUTTER_PROJECT)
            root = Path(tmp)
            self.assertEqual(self._check(tmp), ('flutter', True))
            # The android/ module is scanned in place; nothing is moved.
            self.assertTrue((root / 'android/app/src/main'
                             / 'AndroidManifest.xml').is_file())
            self.assertTrue((root / 'lib/main.dart').is_file())
            self.assertEqual((root / '.gitignore').read_text(),
                             'flutter-ignore\n')

    def test_flutter_project_wrapped_in_folder(self):
        # The wrapper is moved up, so android/ is always at the upload root.
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(Path(tmp) / 'demo', FLUTTER_PROJECT)
            root = Path(tmp)
            self.assertEqual(self._check(tmp), ('flutter', True))
            self.assertFalse((root / 'demo').exists())
            self.assertTrue((root / 'android/app/src/main'
                             / 'AndroidManifest.xml').is_file())
            self.assertTrue((root / 'lib/main.dart').is_file())

    def test_flutter_project_wrapped_in_app_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(Path(tmp) / 'app', FLUTTER_PROJECT)
            root = Path(tmp)
            self.assertEqual(self._check(tmp), ('flutter', True))
            self.assertFalse((root / 'app').exists())
            self.assertTrue((root / 'android/app/src/main'
                             / 'AndroidManifest.xml').is_file())

    def test_flutter_wrapper_named_like_a_child_is_rejected(self):
        # android/android cannot be moved up over itself.
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(Path(tmp) / 'android', FLUTTER_PROJECT)
            self.assertEqual(self._check(tmp), ('', False))

    def test_pubspec_without_android_module_is_not_flutter(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, {'pubspec.yaml': 'name: dart_only\n'})
            self.assertEqual(self._check(tmp), ('', False))

    def test_studio_project_at_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, STUDIO_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))

    def test_studio_project_one_level_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(Path(tmp) / 'MyApp', STUDIO_PROJECT)
            self.assertEqual(self._check(tmp), ('studio', True))
            # Wrapped non-Flutter Android sources are still moved to the root.
            self.assertTrue(
                (Path(tmp) / 'app/src/main/AndroidManifest.xml').is_file())
            self.assertEqual((Path(tmp) / '.gitignore').read_text(),
                             'studio-ignore\n')

    def test_unsupported_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp, {'README.md': 'x'})
            self.assertEqual(self._check(tmp), ('', False))


class FlutterScanPathTests(SimpleTestCase):
    """The scan treats a Flutter android/ module like a Studio project."""

    def _module(self, tmp):
        make_tree(tmp, FLUTTER_PROJECT)
        return Path(tmp) / 'android'

    def test_manifest_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self._module(tmp)
            manifest = get_manifest_file({
                'app_path': module / 'x.apk',
                'app_dir': module,
                'tools_dir': module,
                'zipped': 'flutter',
                'md5': CHECKSUM,
            })
            self.assertEqual(
                manifest, module / 'app/src/main/AndroidManifest.xml')

    def test_kotlin_source_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self._module(tmp)
            self.assertEqual(get_android_src_dir(module, 'flutter'),
                             module / 'app/src/main/kotlin')

    def test_network_security_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = self._module(tmp)
            with mock.patch('mobsf.StaticAnalyzer.views.android.'
                            'network_security.append_scan_status'):
                data = read_netsec_config(
                    CHECKSUM, module, '@xml/netsec', 'flutter')
            self.assertEqual(data, '<network-security-config/>')


class PostScanViewTests(TestCase):
    """Report links, source tree, search and manifest after a ZIP scan."""

    SCANS = {
        'flutter': ('com/example/MainActivity.kt', FLUTTER_PROJECT),
        'studio': ('com/example/MainActivity.java', STUDIO_PROJECT),
    }

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        override = override_settings(UPLD_DIR=tmp.name + '/')
        override.enable()
        self.addCleanup(override.disable)
        self.client = Client()
        self.client.force_login(User.objects.create_superuser('tester'))
        self.auth = api_key(settings.MOBSF_HOME)
        self.upload_dir = Path(tmp.name)

    def _scan(self, app_type):
        rel, files = self.SCANS[app_type]
        make_tree(self.upload_dir / CHECKSUM, files)
        RecentScansDB.objects.create(
            ANALYZER='static_analyzer', SCAN_TYPE='zip', FILE_NAME='a.zip',
            APP_NAME='', PACKAGE_NAME='', VERSION_NAME='', MD5=CHECKSUM,
            TIMESTAMP=timezone.now())
        StaticAnalyzerAndroid.objects.create(MD5=CHECKSUM, APP_TYPE=app_type)
        return rel

    def _assert_views_work(self, app_type):
        rel = self._scan(app_type)
        resp = self.client.post(
            '/api/v1/view_source',
            {'file': rel, 'type': app_type, 'hash': CHECKSUM},
            HTTP_AUTHORIZATION=self.auth)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('MainActivity', resp.json()['data'])
        resp = self.client.post(
            '/api/v1/view_source',
            {'file': 'AndroidManifest.xml', 'type': 'xml', 'hash': CHECKSUM},
            HTTP_AUTHORIZATION=self.auth)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('<manifest', resp.json()['data'])
        resp = self.client.get(
            '/view_file/', {'file': rel, 'type': app_type, 'md5': CHECKSUM})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'MainActivity')
        resp = self.client.get(
            '/source_code/', {'md5': CHECKSUM, 'type': 'java'})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'MainActivity')
        resp = self.client.post(
            '/find/', {'md5': CHECKSUM, 'q': 'MainActivity', 'code': 'java',
                       'search_type': 'content'})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'MainActivity')
        resp = self.client.get(
            f'/manifest_view/{CHECKSUM}/', {'type': app_type})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'com.example.app')

    def test_views_on_flutter_scan(self):
        self._assert_views_work('flutter')

    def test_views_on_studio_scan(self):
        self._assert_views_work('studio')

    def test_source_root_uses_stored_type(self):
        self._scan('flutter')
        base = self.upload_dir / CHECKSUM
        self.assertEqual(android_source_root(base, CHECKSUM), base / 'android')

    def test_source_root_without_scan_record(self):
        base = self.upload_dir / CHECKSUM
        self.assertEqual(android_source_root(base, CHECKSUM), base)

    def test_view_source_stays_inside_android_module(self):
        self._scan('flutter')
        resp = self.client.post(
            '/api/v1/view_source',
            {'file': '../../../pubspec.yaml', 'type': 'flutter',
             'hash': CHECKSUM},
            HTTP_AUTHORIZATION=self.auth)
        self.assertNotEqual(resp.status_code, 200)
