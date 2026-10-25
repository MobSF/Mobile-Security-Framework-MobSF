"""Unit tests for ELF string extraction from Dart/Flutter binaries."""
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.common.binary.elf import ELFChecksec


# Built at runtime so secret scanners do not flag this test file
FAKE_GH_TOKEN = 'ghp' + '_' + 'A1b2C3d4E5' * 3 + 'F6g7H8'
# Dynamic symbols exported by a real Flutter 3.44 libapp.so
LIBAPP_EXPORTS = (
    '_kDartVmSnapshotInstructions', '_kDartVmSnapshotData',
    '_kDartIsolateSnapshotInstructions', '_kDartIsolateSnapshotData')


class _FakeSymbol:

    def __init__(self, name, value):
        self.name = name
        self.value = value


class _FakeLiefELF:
    """Stand-in for a parsed lief ELF: fixed strings and dynamic symbols."""

    def __init__(self, strings, exports=()):
        self.strings = strings
        self.dynamic_symbols = [_FakeSymbol(n, 0x1000) for n in exports]

    def get_symbol(self, name):
        for sym in self.dynamic_symbols:
            if sym.name == name:
                return sym
        raise Exception('no symbol')


class ELFDartStringsTests(SimpleTestCase):
    """Dart strings in libapp.so are not C strings; lief misses them."""

    def _checksec(self, tmp, lief_strings, exports=()):
        path = Path(tmp) / 'libapp.so'
        # Dart string objects: no NUL terminator, separated by headers
        path.write_bytes(
            b'\x7fELF\x02\x01\x01' + b'\x00' * 57
            + b'\x02\x00\x00\x00https://dart-only.example/api'
            + b'\x04\x00\x00\x00' + FAKE_GH_TOKEN.encode() + b'\x01\x02')
        chk = ELFChecksec.__new__(ELFChecksec)
        chk.elf_path = path.as_posix()
        chk.elf_rel = 'lib/arm64-v8a/libapp.so'
        chk.elf = _FakeLiefELF(lief_strings, exports)
        return chk

    def test_dart_snapshot_includes_os_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(tmp, ['GLIBC'], exports=LIBAPP_EXPORTS)
            self.assertTrue(chk.is_dart())
            strings = chk.strings()
        self.assertIn('GLIBC', strings)
        self.assertTrue(
            any('https://dart-only.example/api' in s for s in strings))
        self.assertTrue(any(FAKE_GH_TOKEN in s for s in strings))

    def test_flutter_engine_keeps_lief_strings(self):
        # libflutter.so names the snapshot symbols but does not export them
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(
                tmp, ['_kDartVmSnapshotInstructions', 'Dart_Cleanup'])
            self.assertTrue(chk.is_dart())
            strings = chk.strings()
        self.assertEqual(
            sorted(strings), ['Dart_Cleanup', '_kDartVmSnapshotInstructions'])

    def test_non_dart_binary_keeps_lief_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(tmp, ['GLIBC', 'malloc'])
            self.assertFalse(chk.is_dart())
            strings = chk.strings()
        self.assertEqual(sorted(strings), ['GLIBC', 'malloc'])

    def test_no_lief_strings_falls_back_to_os_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(tmp, [])
            strings = chk.strings()
        self.assertTrue(
            any('https://dart-only.example/api' in s for s in strings))
