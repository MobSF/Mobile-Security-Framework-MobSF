"""Unit tests for native library analysis of extracted APKs."""
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, override_settings

from mobsf.StaticAnalyzer.views.common.binary import lib_analysis

CHECKSUM = 'f1a7f1a7f1a7f1a7f1a7f1a7f1a7f1a7'


class _RecordingChecksec:
    """Stand-in for ELFChecksec that records analysed libraries."""

    analysed = []

    def __init__(self, elf_file, so_rel):
        self.rel = so_rel
        _RecordingChecksec.analysed.append(so_rel)

    def checksec(self):
        return {'name': self.rel}

    def strings(self):
        return ['some string']

    def get_symbols(self):
        return []


class LibraryAnalysisTests(SimpleTestCase):

    def test_apktool_copies_not_analysed_twice(self):
        _RecordingChecksec.analysed = []
        with tempfile.TemporaryDirectory() as upld:
            app_dir = Path(upld) / CHECKSUM
            # Extracted APK and apktool's decoded copy of it
            for rel in ('lib/arm64-v8a/libfoo.so',
                        'lib/x86_64/libfoo.so',
                        'apktool_out/lib/arm64-v8a/libfoo.so',
                        'apktool_out/lib/x86_64/libfoo.so'):
                path = app_dir / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'\x7fELF')
            with override_settings(UPLD_DIR=upld, SO_ANALYSIS_ENABLED=True), \
                    mock.patch.object(lib_analysis, 'ELFChecksec',
                                      _RecordingChecksec), \
                    mock.patch.object(lib_analysis, 'append_scan_status'):
                res = lib_analysis.library_analysis(
                    CHECKSUM, app_dir.as_posix() + '/', 'elf')
        self.assertEqual(sorted(_RecordingChecksec.analysed),
                         ['lib/arm64-v8a/libfoo.so', 'lib/x86_64/libfoo.so'])
        self.assertEqual(len(res['elf_analysis']), 2)
        self.assertEqual(len(res['elf_strings']), 2)
