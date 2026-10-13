import tempfile
import zipfile
from pathlib import Path

from django.test import TestCase

from mobsf.StaticAnalyzer.views.common.shared_func import unzip
from mobsf.StaticAnalyzer.views.windows.windows import _contained_exe


class AppxZipSlipTests(TestCase):
    """Rejected archive names must not be opened as APPX executables."""

    def test_unzip_drops_traversal_names_and_exe_read_stays_inside(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / 'app'
            app_dir.mkdir()
            outside = root / 'secret.exe'
            outside.write_bytes(b'secret-bytes')
            archive = app_dir / 'sample.appx'
            with zipfile.ZipFile(archive, 'w') as zf:
                zf.writestr('legit.exe', b'MZ-legit')
                zf.writestr('../secret.exe', b'nope')
                zf.writestr('/tmp/absolute.exe', b'nope')

            files = unzip('a' * 32, archive.as_posix(), app_dir.as_posix())

            self.assertIn('legit.exe', files)
            self.assertNotIn('../secret.exe', files)
            self.assertFalse(any(name.endswith('absolute.exe') for name in files))
            self.assertEqual(outside.read_bytes(), b'secret-bytes')
            self.assertTrue((app_dir / 'legit.exe').is_file())

            self.assertIsNone(_contained_exe(app_dir.as_posix(), '../secret.exe'))
            self.assertIsNone(
                _contained_exe(app_dir.as_posix(), '/tmp/absolute.exe'))
            contained = _contained_exe(app_dir.as_posix(), 'legit.exe')
            self.assertTrue(
                Path(contained).resolve().is_relative_to(app_dir.resolve()))
