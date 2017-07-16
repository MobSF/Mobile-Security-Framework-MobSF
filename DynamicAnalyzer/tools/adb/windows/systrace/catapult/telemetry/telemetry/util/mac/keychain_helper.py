# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import subprocess

from telemetry.internal.util import binary_manager
from telemetry.core import platform
from telemetry.core import os_version

def _PathForExecutable(executable_name):
  """Fetches the executable from cloud storage, and returns its path."""
  arch_name = platform.GetHostPlatform().GetArchName()
  return binary_manager.FetchPath(executable_name, arch_name, 'mac')

def IsKeychainLocked():
  """
  Returns True if the keychain is locked, or if there is an error determining
  the keychain state.
  """
  path = _PathForExecutable('determine_if_keychain_is_locked')

  child = subprocess.Popen(path, stdout=subprocess.PIPE)
  child.communicate()
  return child.returncode != 0

def DoesKeychainHaveTimeout():
  """
  Returns True if the keychain will lock itself have a period of time.

  This method will trigger a blocking, modal dialog if the keychain is
  locked.
  """
  command = ("/usr/bin/security", "show-keychain-info")
  child = subprocess.Popen(command, stderr=subprocess.PIPE)
  stderr = child.communicate()[1]
  return "no-timeout" not in stderr

def _IsKeychainConfiguredForBots(service_name, account_name):
  """
  Returns True if the keychain entry associated with |service_name| and
  |account_name| is correctly configured for running telemetry tests on bots.

  This method will trigger a blocking, modal dialog if the keychain is
  locked.
  """
  # The executable requires OSX 10.7+ APIs.
  if (platform.GetHostPlatform().GetOSVersionName() <
      os_version.LION):
    return False

  path = _PathForExecutable('determine_if_keychain_entry_is_decryptable')

  command = (path, service_name, account_name)
  child = subprocess.Popen(command)
  child.communicate()
  return child.returncode == 0

def IsKeychainConfiguredForBotsWithChrome():
  return _IsKeychainConfiguredForBots("Chrome Safe Storage",
      "Chrome")

def IsKeychainConfiguredForBotsWithChromium():
  return _IsKeychainConfiguredForBots("Chromium Safe Storage",
      "Chromium")
