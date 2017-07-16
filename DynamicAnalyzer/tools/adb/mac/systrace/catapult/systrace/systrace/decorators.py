# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


def HostOnlyTest(func):
  """Decorator for running unit tests only on the host device.

  This will disable unit tests from running on Android devices.
  """
  return _SkipTestDecoratorHelper(func, ['android'])


def ClientOnlyTest(func):
  """Decorator for running unit tests only on client devices (Android).
  """
  return _SkipTestDecoratorHelper(func, ['win', 'linux', 'mac'])


def Disabled(func):
  """Decorator for not running a unit test on any Trybot platform.
  """
  return _SkipTestDecoratorHelper(func, ['win', 'linux', 'mac', 'android'])


def LinuxMacTest(func):
  return _SkipTestDecoratorHelper(func, ['win', 'android'])


def _SkipTestDecoratorHelper(func, disabled_strings):
  if not hasattr(func, '_disabled_strings'):
    setattr(func, '_disabled_strings', set(disabled_strings))
  return func


def ShouldSkip(test, device):
  """Returns whether the test should be skipped and the reason for it."""
  if hasattr(test, '_disabled_strings'):
    disabled_devices = getattr(test, '_disabled_strings')
    return device in disabled_devices
  return False
