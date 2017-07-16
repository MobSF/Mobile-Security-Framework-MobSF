# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from systrace import decorators
from systrace import util


DEVICE_SERIAL = 'AG8404EC0444AGC'
LIST_TMP_ARGS = ['ls', '/data/local/tmp']
ATRACE_ARGS = ['atrace', '-z', '-t', '10', '-b', '4096']
ADB_SHELL = ['adb', '-s', DEVICE_SERIAL, 'shell']


class UtilTest(unittest.TestCase):

  @decorators.HostOnlyTest
  def test_construct_adb_shell_command(self):
    command = util.construct_adb_shell_command(LIST_TMP_ARGS, None)
    self.assertEqual(' '.join(command), 'adb shell ls /data/local/tmp')

    command = util.construct_adb_shell_command(LIST_TMP_ARGS, DEVICE_SERIAL)
    self.assertEqual(' '.join(command),
                     'adb -s AG8404EC0444AGC shell ls /data/local/tmp')

    command = util.construct_adb_shell_command(ATRACE_ARGS, DEVICE_SERIAL)
    self.assertEqual(' '.join(command),
                     'adb -s AG8404EC0444AGC shell atrace -z -t 10 -b 4096')
