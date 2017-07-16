#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from devil import devil_env
from devil.android import device_errors
from devil.android import md5sum

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error

TEST_OUT_DIR = os.path.join('test', 'out', 'directory')
HOST_MD5_EXECUTABLE = os.path.join(TEST_OUT_DIR, 'md5sum_bin_host')
MD5_DIST = os.path.join(TEST_OUT_DIR, 'md5sum_dist')


class Md5SumTest(unittest.TestCase):

  def setUp(self):
    mocked_attrs = {
      'md5sum_host': HOST_MD5_EXECUTABLE,
      'md5sum_device': MD5_DIST,
    }
    self._patchers = [
      mock.patch('devil.devil_env._Environment.FetchPath',
                 mock.Mock(side_effect=lambda a, device=None: mocked_attrs[a])),
      mock.patch('os.path.exists',
                 new=mock.Mock(return_value=True)),
    ]
    for p in self._patchers:
      p.start()

  def tearDown(self):
    for p in self._patchers:
      p.stop()

  def testCalculateHostMd5Sums_singlePath(self):
    test_path = '/test/host/file.dat'
    mock_get_cmd_output = mock.Mock(
        return_value='0123456789abcdeffedcba9876543210 /test/host/file.dat')
    with mock.patch('devil.utils.cmd_helper.GetCmdOutput',
                    new=mock_get_cmd_output):
      out = md5sum.CalculateHostMd5Sums(test_path)
      self.assertEquals(1, len(out))
      self.assertTrue('/test/host/file.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/test/host/file.dat'])
      mock_get_cmd_output.assert_called_once_with(
          [HOST_MD5_EXECUTABLE, '/test/host/file.dat'])

  def testCalculateHostMd5Sums_list(self):
    test_paths = ['/test/host/file0.dat', '/test/host/file1.dat']
    mock_get_cmd_output = mock.Mock(
        return_value='0123456789abcdeffedcba9876543210 /test/host/file0.dat\n'
                     '123456789abcdef00fedcba987654321 /test/host/file1.dat\n')
    with mock.patch('devil.utils.cmd_helper.GetCmdOutput',
                    new=mock_get_cmd_output):
      out = md5sum.CalculateHostMd5Sums(test_paths)
      self.assertEquals(2, len(out))
      self.assertTrue('/test/host/file0.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/test/host/file0.dat'])
      self.assertTrue('/test/host/file1.dat' in out)
      self.assertEquals('123456789abcdef00fedcba987654321',
                        out['/test/host/file1.dat'])
      mock_get_cmd_output.assert_called_once_with(
          [HOST_MD5_EXECUTABLE, '/test/host/file0.dat',
           '/test/host/file1.dat'])

  def testCalculateHostMd5Sums_generator(self):
    test_paths = ('/test/host/' + p for p in ['file0.dat', 'file1.dat'])
    mock_get_cmd_output = mock.Mock(
        return_value='0123456789abcdeffedcba9876543210 /test/host/file0.dat\n'
                     '123456789abcdef00fedcba987654321 /test/host/file1.dat\n')
    with mock.patch('devil.utils.cmd_helper.GetCmdOutput',
                    new=mock_get_cmd_output):
      out = md5sum.CalculateHostMd5Sums(test_paths)
      self.assertEquals(2, len(out))
      self.assertTrue('/test/host/file0.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/test/host/file0.dat'])
      self.assertTrue('/test/host/file1.dat' in out)
      self.assertEquals('123456789abcdef00fedcba987654321',
                        out['/test/host/file1.dat'])
      mock_get_cmd_output.assert_called_once_with(
          [HOST_MD5_EXECUTABLE, '/test/host/file0.dat', '/test/host/file1.dat'])

  def testCalculateDeviceMd5Sums_noPaths(self):
    device = mock.NonCallableMock()
    device.RunShellCommand = mock.Mock(side_effect=Exception())

    out = md5sum.CalculateDeviceMd5Sums([], device)
    self.assertEquals(0, len(out))

  def testCalculateDeviceMd5Sums_singlePath(self):
    test_path = '/storage/emulated/legacy/test/file.dat'

    device = mock.NonCallableMock()
    device_md5sum_output = [
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file.dat',
    ]
    device.RunShellCommand = mock.Mock(return_value=device_md5sum_output)

    with mock.patch('os.path.getsize', return_value=1337):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(1, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file.dat'])
      self.assertEquals(1, len(device.RunShellCommand.call_args_list))

  def testCalculateDeviceMd5Sums_list(self):
    test_path = ['/storage/emulated/legacy/test/file0.dat',
                 '/storage/emulated/legacy/test/file1.dat']
    device = mock.NonCallableMock()
    device_md5sum_output = [
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file0.dat',
        '123456789abcdef00fedcba987654321 '
            '/storage/emulated/legacy/test/file1.dat',
    ]
    device.RunShellCommand = mock.Mock(return_value=device_md5sum_output)

    with mock.patch('os.path.getsize', return_value=1337):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(2, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file0.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file0.dat'])
      self.assertTrue('/storage/emulated/legacy/test/file1.dat' in out)
      self.assertEquals('123456789abcdef00fedcba987654321',
                        out['/storage/emulated/legacy/test/file1.dat'])
      self.assertEquals(1, len(device.RunShellCommand.call_args_list))

  def testCalculateDeviceMd5Sums_generator(self):
    test_path = ('/storage/emulated/legacy/test/file%d.dat' % n
                 for n in xrange(0, 2))

    device = mock.NonCallableMock()
    device_md5sum_output = [
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file0.dat',
        '123456789abcdef00fedcba987654321 '
            '/storage/emulated/legacy/test/file1.dat',
    ]
    device.RunShellCommand = mock.Mock(return_value=device_md5sum_output)

    with mock.patch('os.path.getsize', return_value=1337):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(2, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file0.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file0.dat'])
      self.assertTrue('/storage/emulated/legacy/test/file1.dat' in out)
      self.assertEquals('123456789abcdef00fedcba987654321',
                        out['/storage/emulated/legacy/test/file1.dat'])
      self.assertEquals(1, len(device.RunShellCommand.call_args_list))

  def testCalculateDeviceMd5Sums_singlePath_linkerWarning(self):
    # See crbug/479966
    test_path = '/storage/emulated/legacy/test/file.dat'

    device = mock.NonCallableMock()
    device_md5sum_output = [
        'WARNING: linker: /data/local/tmp/md5sum/md5sum_bin: '
            'unused DT entry: type 0x1d arg 0x15db',
        'THIS_IS_NOT_A_VALID_CHECKSUM_ZZZ some random text',
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file.dat',
    ]
    device.RunShellCommand = mock.Mock(return_value=device_md5sum_output)

    with mock.patch('os.path.getsize', return_value=1337):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(1, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file.dat'])
      self.assertEquals(1, len(device.RunShellCommand.call_args_list))

  def testCalculateDeviceMd5Sums_list_fileMissing(self):
    test_path = ['/storage/emulated/legacy/test/file0.dat',
                 '/storage/emulated/legacy/test/file1.dat']
    device = mock.NonCallableMock()
    device_md5sum_output = [
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file0.dat',
        '[0819/203513:ERROR:md5sum.cc(25)] Could not open file asdf',
        '',
    ]
    device.RunShellCommand = mock.Mock(return_value=device_md5sum_output)

    with mock.patch('os.path.getsize', return_value=1337):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(1, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file0.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file0.dat'])
      self.assertEquals(1, len(device.RunShellCommand.call_args_list))

  def testCalculateDeviceMd5Sums_requiresBinary(self):
    test_path = '/storage/emulated/legacy/test/file.dat'

    device = mock.NonCallableMock()
    device.adb = mock.NonCallableMock()
    device.adb.Push = mock.Mock()
    device_md5sum_output = [
        'WARNING: linker: /data/local/tmp/md5sum/md5sum_bin: '
            'unused DT entry: type 0x1d arg 0x15db',
        'THIS_IS_NOT_A_VALID_CHECKSUM_ZZZ some random text',
        '0123456789abcdeffedcba9876543210 '
            '/storage/emulated/legacy/test/file.dat',
    ]
    error = device_errors.AdbShellCommandFailedError('cmd', 'out', 2)
    device.RunShellCommand = mock.Mock(
        side_effect=(error, '', device_md5sum_output))

    with mock.patch('os.path.isdir', return_value=True), (
         mock.patch('os.path.getsize', return_value=1337)):
      out = md5sum.CalculateDeviceMd5Sums(test_path, device)
      self.assertEquals(1, len(out))
      self.assertTrue('/storage/emulated/legacy/test/file.dat' in out)
      self.assertEquals('0123456789abcdeffedcba9876543210',
                        out['/storage/emulated/legacy/test/file.dat'])
      self.assertEquals(3, len(device.RunShellCommand.call_args_list))
      device.adb.Push.assert_called_once_with(
          'test/out/directory/md5sum_dist', '/data/local/tmp/md5sum')


if __name__ == '__main__':
  unittest.main(verbosity=2)

