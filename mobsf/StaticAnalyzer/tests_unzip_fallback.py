"""Tests for the OS unzip fallback symlink guard."""
import os
import shutil
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from mobsf.MobSF.utils import set_permissions
from mobsf.StaticAnalyzer.views.common.shared_func import (
    neutralize_zip_special_modes,
    os_unzip,
    remove_external_symlinks,
    unzip,
)


def _require_symlink(path, target):
    try:
        os.symlink(target, path)
    except (OSError, NotImplementedError):
        raise unittest.SkipTest('Symlinks not supported')


def _mode_of(data, name):
    needle = name.encode()
    pos = 0
    while True:
        cd = data.find(b'PK\x01\x02', pos)
        if cd < 0:
            raise AssertionError(name)
        name_len = struct.unpack_from('<H', data, cd + 28)[0]
        filename = data[cd + 46:cd + 46 + name_len]
        if filename == needle:
            external_attr = struct.unpack_from('<I', data, cd + 38)[0]
            return (external_attr >> 16) & 0xFFFF
        pos = cd + 4


def _symlink_zip(archive, target, corrupt_size=False):
    with zipfile.ZipFile(archive, 'w') as handle:
        info = zipfile.ZipInfo('MainActivity.java')
        info.external_attr = (0o120777 << 16)
        info.create_system = 3
        handle.writestr(info, target)
        handle.writestr(
            'app/src/main/AndroidManifest.xml',
            '<manifest package="com.poc.app"/>')
        handle.writestr(
            'app/src/main/java/com/poc/app/Dummy.java',
            'class Dummy {}')
    if not corrupt_size:
        return
    data = bytearray(archive.read_bytes())
    eocd = data.rfind(b'PK\x05\x06')
    data[eocd + 12:eocd + 16] = struct.pack('<I', 5)
    archive.write_bytes(data)


class UnzipFallbackTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.secret = self.root / 'secret.txt'
        self.secret.write_text('SENTINEL\n')
        self.archive = self.root / 'sample.zip'
        self.ext = self.root / 'ext'
        self.ext.mkdir()
        patcher = mock.patch(
            'mobsf.StaticAnalyzer.views.common.shared_func.append_scan_status')
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_neutralize_rewrites_symlink_mode(self):
        _symlink_zip(self.archive, str(self.secret))
        patched = neutralize_zip_special_modes(
            self.archive.as_posix(), self.ext.as_posix())
        with zipfile.ZipFile(patched) as handle:
            info = handle.getinfo('MainActivity.java')
        mode = (info.external_attr >> 16) & 0xFFFF
        self.assertEqual(mode, 0o100644)
        with zipfile.ZipFile(self.archive) as handle:
            original = handle.getinfo('MainActivity.java')
        self.assertTrue(stat.S_ISLNK(original.external_attr >> 16))

    def test_neutralize_corrupt_eocd_size(self):
        _symlink_zip(self.archive, str(self.secret), corrupt_size=True)
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(self.archive)
        patched = neutralize_zip_special_modes(
            self.archive.as_posix(), self.ext.as_posix())
        mode = _mode_of(Path(patched).read_bytes(), 'MainActivity.java')
        self.assertEqual(mode, 0o100644)

    def test_remove_keeps_internal_and_drops_external(self):
        inside = self.ext / 'Dummy.java'
        inside.write_text('class Dummy {}')
        internal = self.ext / 'Internal.java'
        _require_symlink(internal, 'Dummy.java')
        external = self.ext / 'External.java'
        _require_symlink(external, self.secret)
        if not hasattr(os, 'mkfifo'):
            pipe = None
        else:
            pipe = self.ext / 'pipe'
            os.mkfifo(pipe)
        remove_external_symlinks(self.ext.as_posix())
        self.assertTrue(internal.is_symlink())
        self.assertFalse(external.exists())
        if pipe is not None:
            self.assertFalse(pipe.exists())
        self.assertEqual(self.secret.read_text(), 'SENTINEL\n')
        self.assertTrue(inside.is_file())

    def test_set_permissions_does_not_follow_symlink(self):
        self.secret.chmod(0o600)
        link = self.ext / 'link'
        _require_symlink(link, self.secret)
        set_permissions(self.ext.as_posix())
        self.assertEqual(stat.S_IMODE(self.secret.stat().st_mode), 0o600)
        self.assertTrue(link.is_symlink())

    def test_os_unzip_skips_windows(self):
        with mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.platform.system',
                return_value='Windows'):
            listed = os_unzip(
                'a' * 32,
                self.archive.as_posix(),
                self.ext.as_posix())
        self.assertEqual(listed, [])

    def test_corrupt_archive_fallback_does_not_follow_symlink(self):
        if not shutil.which('unzip') or os.name == 'nt':
            self.skipTest('OS unzip is not available')
        _symlink_zip(self.archive, str(self.secret), corrupt_size=True)
        unzip(
            'b' * 32,
            self.archive.as_posix(),
            self.ext.as_posix())
        extracted = self.ext / 'MainActivity.java'
        self.assertTrue(extracted.is_file())
        self.assertFalse(extracted.is_symlink())
        self.assertNotIn('SENTINEL', extracted.read_text())
        self.assertEqual(self.secret.read_text(), 'SENTINEL\n')
        manifest = self.ext / 'app/src/main/AndroidManifest.xml'
        self.assertTrue(manifest.is_file())

    def test_budgeted_open_failure_skips_fallback(self):
        _symlink_zip(self.archive, str(self.secret), corrupt_size=True)
        unzip(
            'c' * 32,
            self.archive.as_posix(),
            self.ext.as_posix(),
            size_budget={'used': 0})
        self.assertFalse((self.ext / 'MainActivity.java').exists())
