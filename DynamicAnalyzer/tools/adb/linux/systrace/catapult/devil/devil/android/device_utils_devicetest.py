#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Unit tests for the contents of device_utils.py (mostly DeviceUtils).
The test will invoke real devices
"""

import os
import posixpath
import sys
import tempfile
import unittest

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', )))

from devil.android import device_test_case
from devil.android import device_utils
from devil.android.sdk import adb_wrapper
from devil.utils import cmd_helper

_OLD_CONTENTS = "foo"
_NEW_CONTENTS = "bar"
_DEVICE_DIR = "/data/local/tmp/device_utils_test"
_SUB_DIR = "sub"
_SUB_DIR1 = "sub1"
_SUB_DIR2 = "sub2"


class DeviceUtilsPushDeleteFilesTest(device_test_case.DeviceTestCase):

  def setUp(self):
    super(DeviceUtilsPushDeleteFilesTest, self).setUp()
    self.adb = adb_wrapper.AdbWrapper(self.serial)
    self.adb.WaitForDevice()
    self.device = device_utils.DeviceUtils(
        self.adb, default_timeout=10, default_retries=0)

  @staticmethod
  def _MakeTempFile(contents):
    """Make a temporary file with the given contents.

    Args:
      contents: string to write to the temporary file.

    Returns:
      the tuple contains the absolute path to the file and the file name
    """
    fi, path = tempfile.mkstemp(text=True)
    with os.fdopen(fi, 'w') as f:
      f.write(contents)
    file_name = os.path.basename(path)
    return (path, file_name)

  @staticmethod
  def _MakeTempFileGivenDir(directory, contents):
    """Make a temporary file under the given directory
    with the given contents

    Args:
      directory: the temp directory to create the file
      contents: string to write to the temp file

    Returns:
      the list contains the absolute path to the file and the file name
    """
    fi, path = tempfile.mkstemp(dir=directory, text=True)
    with os.fdopen(fi, 'w') as f:
      f.write(contents)
    file_name = os.path.basename(path)
    return (path, file_name)

  @staticmethod
  def _ChangeTempFile(path, contents):
    with os.open(path, 'w') as f:
      f.write(contents)

  @staticmethod
  def _DeleteTempFile(path):
    os.remove(path)

  def testPushChangedFiles_noFileChange(self):
    (host_file_path, file_name) = self._MakeTempFile(_OLD_CONTENTS)
    device_file_path = "%s/%s" % (_DEVICE_DIR, file_name)
    self.adb.Push(host_file_path, device_file_path)
    self.device.PushChangedFiles([(host_file_path, device_file_path)])
    result = self.device.RunShellCommand(
        ['cat', device_file_path], check_return=True, single_line=True)
    self.assertEqual(_OLD_CONTENTS, result)

    cmd_helper.RunCmd(['rm', host_file_path])
    self.device.RemovePath(_DEVICE_DIR, recursive=True, force=True)

  def testPushChangedFiles_singleFileChange(self):
    (host_file_path, file_name) = self._MakeTempFile(_OLD_CONTENTS)
    device_file_path = "%s/%s" % (_DEVICE_DIR, file_name)
    self.adb.Push(host_file_path, device_file_path)

    with open(host_file_path, 'w') as f:
      f.write(_NEW_CONTENTS)
    self.device.PushChangedFiles([(host_file_path, device_file_path)])
    result = self.device.RunShellCommand(
        ['cat', device_file_path], check_return=True, single_line=True)
    self.assertEqual(_NEW_CONTENTS, result)

    cmd_helper.RunCmd(['rm', host_file_path])
    self.device.RemovePath(_DEVICE_DIR, recursive=True, force=True)

  def testDeleteFiles(self):
    host_tmp_dir = tempfile.mkdtemp()
    (host_file_path, file_name) = self._MakeTempFileGivenDir(
        host_tmp_dir, _OLD_CONTENTS)

    device_file_path = "%s/%s" % (_DEVICE_DIR, file_name)
    self.adb.Push(host_file_path, device_file_path)

    cmd_helper.RunCmd(['rm', host_file_path])
    self.device.PushChangedFiles([(host_tmp_dir, _DEVICE_DIR)],
                                 delete_device_stale=True)
    filenames = self.device.ListDirectory(_DEVICE_DIR)
    self.assertEqual([], filenames)

    cmd_helper.RunCmd(['rm', '-rf', host_tmp_dir])
    self.device.RemovePath(_DEVICE_DIR, recursive=True, force=True)

  def testPushAndDeleteFiles_noSubDir(self):
    host_tmp_dir = tempfile.mkdtemp()
    (host_file_path1, file_name1) = self._MakeTempFileGivenDir(
        host_tmp_dir, _OLD_CONTENTS)
    (host_file_path2, file_name2) = self._MakeTempFileGivenDir(
        host_tmp_dir, _OLD_CONTENTS)

    device_file_path1 = "%s/%s" % (_DEVICE_DIR, file_name1)
    device_file_path2 = "%s/%s" % (_DEVICE_DIR, file_name2)
    self.adb.Push(host_file_path1, device_file_path1)
    self.adb.Push(host_file_path2, device_file_path2)

    with open(host_file_path1, 'w') as f:
      f.write(_NEW_CONTENTS)
    cmd_helper.RunCmd(['rm', host_file_path2])

    self.device.PushChangedFiles([(host_tmp_dir, _DEVICE_DIR)],
                                   delete_device_stale=True)
    result = self.device.RunShellCommand(
        ['cat', device_file_path1], check_return=True, single_line=True)
    self.assertEqual(_NEW_CONTENTS, result)

    filenames = self.device.ListDirectory(_DEVICE_DIR)
    self.assertEqual([file_name1], filenames)

    cmd_helper.RunCmd(['rm', '-rf', host_tmp_dir])
    self.device.RemovePath(_DEVICE_DIR, recursive=True, force=True)

  def testPushAndDeleteFiles_SubDir(self):
    host_tmp_dir = tempfile.mkdtemp()
    host_sub_dir1 = "%s/%s" % (host_tmp_dir, _SUB_DIR1)
    host_sub_dir2 = "%s/%s/%s" % (host_tmp_dir, _SUB_DIR, _SUB_DIR2)
    cmd_helper.RunCmd(['mkdir', '-p', host_sub_dir1])
    cmd_helper.RunCmd(['mkdir', '-p', host_sub_dir2])

    (host_file_path1, file_name1) = self._MakeTempFileGivenDir(
        host_tmp_dir, _OLD_CONTENTS)
    (host_file_path2, file_name2) = self._MakeTempFileGivenDir(
        host_tmp_dir, _OLD_CONTENTS)
    (host_file_path3, file_name3) = self._MakeTempFileGivenDir(
        host_sub_dir1, _OLD_CONTENTS)
    (host_file_path4, file_name4) = self._MakeTempFileGivenDir(
        host_sub_dir2, _OLD_CONTENTS)

    device_file_path1 = "%s/%s" % (_DEVICE_DIR, file_name1)
    device_file_path2 = "%s/%s" % (_DEVICE_DIR, file_name2)
    device_file_path3 = "%s/%s/%s" % (_DEVICE_DIR, _SUB_DIR1, file_name3)
    device_file_path4 = "%s/%s/%s/%s" % (_DEVICE_DIR, _SUB_DIR,
                                         _SUB_DIR2, file_name4)

    self.adb.Push(host_file_path1, device_file_path1)
    self.adb.Push(host_file_path2, device_file_path2)
    self.adb.Push(host_file_path3, device_file_path3)
    self.adb.Push(host_file_path4, device_file_path4)

    with open(host_file_path1, 'w') as f:
      f.write(_NEW_CONTENTS)
    cmd_helper.RunCmd(['rm', host_file_path2])
    cmd_helper.RunCmd(['rm', host_file_path4])

    self.device.PushChangedFiles([(host_tmp_dir, _DEVICE_DIR)],
                                   delete_device_stale=True)
    result = self.device.RunShellCommand(
        ['cat', device_file_path1], check_return=True, single_line=True)
    self.assertEqual(_NEW_CONTENTS, result)

    filenames = self.device.ListDirectory(_DEVICE_DIR)
    self.assertIn(file_name1, filenames)
    self.assertIn(_SUB_DIR1, filenames)
    self.assertIn(_SUB_DIR, filenames)
    self.assertEqual(3, len(filenames))

    result = self.device.RunShellCommand(
        ['cat', device_file_path3], check_return=True, single_line=True)
    self.assertEqual(_OLD_CONTENTS, result)

    filenames = self.device.ListDirectory(
        posixpath.join(_DEVICE_DIR, _SUB_DIR, _SUB_DIR2))
    self.assertEqual([], filenames)

    cmd_helper.RunCmd(['rm', '-rf', host_tmp_dir])
    self.device.RemovePath(_DEVICE_DIR, recursive=True, force=True)

  def testRestartAdbd(self):
    def get_adbd_pid():
      # TODO(catapult:#3215): Migrate to device.GetPids().
      ps_output = self.device.RunShellCommand(['ps'], check_return=True)
      for ps_line in ps_output:
        if 'adbd' in ps_line:
          return ps_line.split()[1]
      self.fail('Unable to find adbd')

    old_adbd_pid = get_adbd_pid()
    self.device.RestartAdbd()
    new_adbd_pid = get_adbd_pid()
    self.assertNotEqual(old_adbd_pid, new_adbd_pid)


if __name__ == '__main__':
  unittest.main()
