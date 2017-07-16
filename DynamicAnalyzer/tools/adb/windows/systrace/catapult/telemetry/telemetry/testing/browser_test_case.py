# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from functools import wraps
import logging
import os
import sys
import types
import unittest

from telemetry.internal.browser import browser_finder
from telemetry.internal.util import path
from telemetry.testing import options_for_unittests

current_browser_options = None
current_browser = None


class _MetaBrowserTestCase(type):
  """Metaclass for BrowserTestCase.

  The metaclass wraps all test* methods of all subclasses of BrowserTestCase to
  print browser standard output and log upon failure.
  """

  def __new__(mcs, name, bases, dct):
    new_dct = {}
    for attributeName, attribute in dct.iteritems():
      if (isinstance(attribute, types.FunctionType) and
          attributeName.startswith('test')):
        attribute = mcs._PrintBrowserStandardOutputAndLogOnFailure(attribute)
      new_dct[attributeName] = attribute
    return type.__new__(mcs, name, bases, new_dct)

  @staticmethod
  def _PrintBrowserStandardOutputAndLogOnFailure(method):
    @wraps(method)
    def WrappedMethod(self):
      try:  # pylint: disable=broad-except
        method(self)
      except Exception:
        exc_info = sys.exc_info()

        if self._browser:
          self._browser.DumpStateUponFailure()
        else:
          logging.warning('Cannot dump browser state: No browser.')

        # Re-raise the original exception. Note that we can't just use 'raise'
        # without any arguments because an exception might have been thrown when
        # dumping the state of the browser.
        raise exc_info[0], exc_info[1], exc_info[2]
    return WrappedMethod


def teardown_browser():
  global current_browser
  global current_browser_options

  if current_browser:
    current_browser.Close()
    current_browser.platform.network_controller.Close()
  current_browser = None
  current_browser_options = None


class BrowserTestCase(unittest.TestCase):
  __metaclass__ = _MetaBrowserTestCase

  @classmethod
  def setUpClass(cls):
    cls._platform = None
    global current_browser
    global current_browser_options

    options = options_for_unittests.GetCopy()

    cls.CustomizeBrowserOptions(options.browser_options)
    if not current_browser or (current_browser_options !=
                               options.browser_options):
      if current_browser:
        teardown_browser()

      browser_to_create = browser_finder.FindBrowser(options)
      if not browser_to_create:
        raise Exception('No browser found, cannot continue test.')
      cls._platform = browser_to_create.platform
      cls._platform.network_controller.InitializeIfNeeded()

      try:
        current_browser = browser_to_create.Create(options)
        current_browser_options = options.browser_options
      except:
        cls.tearDownClass()
        raise
    cls._browser = current_browser
    cls._device = options.remote_platform_options.device

  @classmethod
  def tearDownClass(cls):
    if cls._platform:
      cls._platform.StopAllLocalServers()
      cls._platform.network_controller.Close()

  @classmethod
  def CustomizeBrowserOptions(cls, options):
    """Override to add test-specific options to the BrowserOptions object"""
    pass

  @classmethod
  def UrlOfUnittestFile(cls, filename):
    cls._platform.SetHTTPServerDirectories(path.GetUnittestDataDir())
    file_path = os.path.join(path.GetUnittestDataDir(), filename)
    return cls._platform.http_server.UrlOf(file_path)
