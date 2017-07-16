# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import platform
import sys

import py_utils

def GetOSAndArchForCurrentDesktopPlatform():
  os_name = GetOSNameForCurrentDesktopPlatform()
  return os_name, GetArchForCurrentDesktopPlatform(os_name)


def GetOSNameForCurrentDesktopPlatform():
  if py_utils.IsRunningOnCrosDevice():
    return 'chromeos'
  if sys.platform.startswith('linux'):
    return 'linux'
  if sys.platform == 'darwin':
    return 'mac'
  if sys.platform == 'win32':
    return 'win'
  return sys.platform


def GetArchForCurrentDesktopPlatform(os_name):
  if os_name == 'chromeos':
    # Current tests outside of telemetry don't run on chromeos, and
    # platform.machine is not the way telemetry gets the arch name on chromeos.
    raise NotImplementedError()
  return platform.machine()


def GetChromeApkOsVersion(version_name):
  version = version_name[0]
  assert version.isupper(), (
      'First character of versions name %s was not an uppercase letter.')
  if version < 'L':
    return 'k'
  elif version > 'M':
    return 'n'
  return 'l'


def ChromeBinariesConfigPath():
  return os.path.realpath(os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'chrome_binaries.json'))
