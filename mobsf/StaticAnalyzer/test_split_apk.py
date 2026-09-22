# -*- coding: utf_8 -*-
"""Tests for split APK native-library extraction."""
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

from django.test import TestCase

from mobsf.MobSF import settings
from mobsf.StaticAnalyzer.views.android.xapk import (
    _extract_sibling_splits,
    handle_split_apk,
)
from mobsf.StaticAnalyzer.views.common.shared_func import unzip


def _zip_bytes(members):
    """Return zip bytes for ``(name, data)`` members."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w') as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buf.getvalue()


def _write_zip(path, members):
    path.write_bytes(_zip_bytes(members))


class SplitApkExtractionTests(TestCase):
    """Sibling split extracts stay inside one uncompressed-size budget."""

    def test_extracts_native_libraries_from_abi_splits(self):
        checksum = 'a' * 32
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            container = app_dir / f'{checksum}.apk'
            _write_zip(container, [
                ('base.apk', _zip_bytes([
                    ('AndroidManifest.xml', b'<manifest/>'),
                ])),
                ('config.armeabi_v7a.apk', _zip_bytes([
                    ('lib/armeabi-v7a/libapp.so', b'\x7fELFlibapp'),
                    ('lib/armeabi-v7a/libflutter.so', b'\x7fELFflutter'),
                ])),
                ('../outside.apk', b'pwned'),
            ])
            found = handle_split_apk({
                'md5': checksum,
                'app_dir': app_dir,
            })
            lib_root = (
                app_dir / 'split_apks' / 'config.armeabi_v7a'
                / 'lib' / 'armeabi-v7a')
            self.assertTrue(found)
            self.assertEqual(
                (lib_root / 'libapp.so').read_bytes(), b'\x7fELFlibapp')
            self.assertTrue((lib_root / 'libflutter.so').is_file())
            self.assertFalse((Path(tmp).parent / 'outside.apk').exists())
            self.assertFalse((app_dir / 'outside.apk').exists())

    def test_sibling_splits_share_one_uncompressed_budget(self):
        checksum = 'b' * 32
        old_limit = settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE
        settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE = 100
        try:
            with tempfile.TemporaryDirectory() as tmp:
                app_dir = Path(tmp)
                primary = app_dir / 'base.apk'
                primary.write_bytes(b'base')
                first = app_dir / 'config.a.apk'
                second = app_dir / 'config.b.apk'
                _write_zip(first, [('lib/a.so', b'A' * 60)])
                _write_zip(second, [('lib/b.so', b'B' * 60)])
                _extract_sibling_splits(
                    checksum,
                    app_dir,
                    primary,
                    [primary, first, second],
                    {'used': 0},
                )
                self.assertTrue(
                    (app_dir / 'split_apks' / 'config.a' / 'lib' / 'a.so').is_file())
                self.assertFalse(
                    (app_dir / 'split_apks' / 'config.b' / 'lib' / 'b.so').exists())
        finally:
            settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE = old_limit

    def test_unzip_budget_is_shared_and_skips_os_fallback(self):
        old_limit = settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE
        settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE = 100
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                first = root / 'a.zip'
                second = root / 'b.zip'
                _write_zip(first, [('a.bin', b'A' * 60)])
                _write_zip(second, [('b.bin', b'B' * 60)])
                budget = {'used': 0}
                unzip('c' * 32, first.as_posix(), (root / 'o1').as_posix(), budget)
                unzip('c' * 32, second.as_posix(), (root / 'o2').as_posix(), budget)
                missing = unzip(
                    'c' * 32,
                    (root / 'missing.zip').as_posix(),
                    (root / 'o3').as_posix(),
                    budget,
                )
                self.assertTrue((root / 'o1' / 'a.bin').is_file())
                self.assertFalse((root / 'o2' / 'b.bin').exists())
                self.assertEqual(missing, [])
                self.assertGreaterEqual(budget['used'], 100)
        finally:
            settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE = old_limit

    def test_skips_symlink_splits(self):
        checksum = 'd' * 32
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            primary = app_dir / 'base.apk'
            primary.write_bytes(b'base')
            real_zip = app_dir / 'real.zip'
            _write_zip(real_zip, [('pwned.txt', b'PWNED')])
            link = app_dir / 'evil.apk'
            link.symlink_to(real_zip)
            _extract_sibling_splits(
                checksum,
                app_dir,
                primary,
                [primary, link],
                {'used': 0},
            )
            self.assertFalse((app_dir / 'split_apks').exists())
            self.assertFalse(list(app_dir.rglob('pwned.txt')))
