#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import logging
import subprocess
import platform
import time


def ShouldStartXvfb():
  return platform.system() == 'Linux'


def StartXvfb():
  display = ':99'
  xvfb_command = ['Xvfb', display, '-screen', '0', '1024x769x24', '-ac']
  xvfb_process = subprocess.Popen(
      xvfb_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  time.sleep(0.2)
  returncode = xvfb_process.poll()
  if returncode is None:
    os.environ['DISPLAY'] = display
  else:
    logging.error('Xvfb did not start, returncode: %s, stdout:\n%s',
                  returncode, xvfb_process.stdout.read())
    xvfb_process = None
  return xvfb_process
