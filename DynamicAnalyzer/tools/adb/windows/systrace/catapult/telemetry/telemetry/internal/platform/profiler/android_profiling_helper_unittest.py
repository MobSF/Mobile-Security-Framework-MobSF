# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import pickle
import re
import shutil
import tempfile
import time
import unittest

from telemetry.core import util
from telemetry import decorators
from telemetry.internal.platform.profiler import android_profiling_helper
from telemetry.testing import simple_mock
from telemetry.testing import tab_test_case


def _GetLibrariesMappedIntoProcesses(device, pids):
  libs = set()
  for pid in pids:
    maps_file = '/proc/%d/maps' % pid
    maps = device.ReadFile(maps_file, as_root=True).splitlines()
    for map_line in maps:
      lib = re.match(r'.*\s(/.*[.]so)$', map_line)
      if lib:
        libs.add(lib.group(1))
  return libs


class TestFileMetadataMatches(unittest.TestCase):
  def setUp(self):
    self.tempdir = tempfile.mkdtemp()
    self.filename_a = os.path.join(self.tempdir, 'filea')
    self.filename_b = os.path.join(self.tempdir, 'fileb')

    with open(self.filename_a, 'w') as f:
      f.write('testing')

  def tearDown(self):
    shutil.rmtree(self.tempdir)

  def testDoesntMatchNonExistant(self):
    self.assertFalse(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testDoesntMatchJustExistence(self):
    with open(self.filename_b, 'w') as f:
      f.write('blah')

    self.assertFalse(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testDoesntMatchCopy(self):
    # This test can run so fast that the file system doesn't have enough
    # accuracy to differentiate between the copy and initial file times.
    # Hence we need to guarantee a delay here.
    time.sleep(3)
    shutil.copy(self.filename_a, self.filename_b)
    self.assertFalse(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testMatchesAfterCopy2(self):
    shutil.copy2(self.filename_a, self.filename_b)
    self.assertTrue(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testDoesntMatchAfterCopy2ThenModify(self):
    shutil.copy2(self.filename_a, self.filename_b)

    filea = open(self.filename_a, 'w')
    filea.write('moar testing!')
    filea.close()

    self.assertFalse(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testDoesntMatchAfterCopy2ThenModifyStats(self):
    shutil.copy2(self.filename_a, self.filename_b)
    os.utime(self.filename_a, (20, 20))
    self.assertFalse(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))

  def testMatchesAfterCopyStatWithDifferentContent(self):
    fileb = open(self.filename_b, 'w')
    fileb.write('blahing')
    fileb.close()

    shutil.copystat(self.filename_a, self.filename_b)

    self.assertTrue(
        android_profiling_helper._FileMetadataMatches(
            self.filename_a, self.filename_b))


class TestAndroidProfilingHelper(unittest.TestCase):

  @decorators.Enabled('linux')
  def testGetRequiredLibrariesForPerfProfile(self):
    perf_output = os.path.join(
        util.GetUnittestDataDir(), 'sample_perf_report_output.txt')
    with open(perf_output) as f:
      perf_output = f.read()

    mock_popen = simple_mock.MockObject()
    mock_popen.ExpectCall('communicate').WillReturn([None, perf_output])

    mock_subprocess = simple_mock.MockObject()
    mock_subprocess.ExpectCall(
        'Popen').WithArgs(simple_mock.DONT_CARE).WillReturn(mock_popen)
    mock_subprocess.SetAttribute('PIPE', simple_mock.MockObject())

    real_subprocess = android_profiling_helper.subprocess
    android_profiling_helper.subprocess = mock_subprocess
    try:
      libs = android_profiling_helper.GetRequiredLibrariesForPerfProfile('foo')
      self.assertEqual(libs, set([
          '/data/app-lib/com.google.android.apps.chrome-2/libchrome.2016.0.so',
          '/system/lib/libart.so',
          '/system/lib/libc.so',
          '/system/lib/libm.so']))
    finally:
      android_profiling_helper.subprocess = real_subprocess

  @decorators.Enabled('android')
  def testGetRequiredLibrariesForVTuneProfile(self):
    vtune_db_output = os.path.join(
        util.GetUnittestDataDir(), 'sample_vtune_db_output')
    with open(vtune_db_output, 'rb') as f:
      vtune_db_output = pickle.load(f)

    mock_cursor = simple_mock.MockObject()
    mock_cursor.ExpectCall(
        'execute').WithArgs(simple_mock.DONT_CARE).WillReturn(vtune_db_output)

    mock_conn = simple_mock.MockObject()
    mock_conn.ExpectCall('cursor').WillReturn(mock_cursor)
    mock_conn.ExpectCall('close')

    mock_sqlite3 = simple_mock.MockObject()
    mock_sqlite3.ExpectCall(
        'connect').WithArgs(simple_mock.DONT_CARE).WillReturn(mock_conn)

    real_sqlite3 = android_profiling_helper.sqlite3
    android_profiling_helper.sqlite3 = mock_sqlite3
    try:
      libs = android_profiling_helper.GetRequiredLibrariesForVTuneProfile('foo')
      self.assertEqual(libs, set([
          '/data/app-lib/com.google.android.apps.chrome-1/libchrome.2019.0.so',
          '/system/lib/libdvm.so',
          '/system/lib/libc.so',
          '/system/lib/libm.so']))
    finally:
      android_profiling_helper.sqlite3 = real_sqlite3


class TestAndroidProfilingHelperTabTestCase(tab_test_case.TabTestCase):

  def setUp(self):
    super(TestAndroidProfilingHelperTabTestCase, self).setUp()
    # pylint: disable=protected-access
    browser_backend = self._browser._browser_backend
    self._device = browser_backend.device()

  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  @decorators.Disabled('all')
  def testCreateSymFs(self):
    # pylint: disable=protected-access
    browser_pid = self._browser._browser_backend.pid
    pids = ([browser_pid] +
        self._browser._platform_backend.GetChildPids(browser_pid))
    libs = _GetLibrariesMappedIntoProcesses(self._device, pids)
    assert libs

    symfs_dir = tempfile.mkdtemp()
    try:
      kallsyms = android_profiling_helper.CreateSymFs(self._device, symfs_dir,
                                                      libs)

      # Check that we have kernel symbols.
      assert os.path.exists(kallsyms)

      is_unstripped = re.compile(r'^/data/app(-lib)?/.*\.so$')
      has_unstripped = False

      # Check that all requested libraries are present.
      for lib in libs:
        has_unstripped = has_unstripped or is_unstripped.match(lib)
        assert os.path.exists(os.path.join(symfs_dir, lib[1:])), \
            '%s not found in symfs' % lib

      # Make sure we found at least one unstripped library.
      assert has_unstripped
    finally:
      shutil.rmtree(symfs_dir)

  # Test fails: crbug.com/437081
  # @decorators.Enabled('android')
  @decorators.Disabled('all')
  def testGetToolchainBinaryPath(self):
    with tempfile.NamedTemporaryFile() as libc:
      self._device.PullFile('/system/lib/libc.so', libc.name)
      path = android_profiling_helper.GetToolchainBinaryPath(libc.name,
                                                             'objdump')
      assert path and os.path.exists(path)
