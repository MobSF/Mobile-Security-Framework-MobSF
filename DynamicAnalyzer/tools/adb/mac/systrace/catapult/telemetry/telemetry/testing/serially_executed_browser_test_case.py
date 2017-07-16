# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import inspect
import logging
import re
import unittest

from py_utils import cloud_storage
from telemetry.internal.browser import browser_finder
from telemetry.testing import browser_test_context
from telemetry.util import wpr_modes


DEFAULT_LOG_FORMAT = (
  '(%(levelname)s) %(asctime)s %(module)s.%(funcName)s:%(lineno)d  '
  '%(message)s')


class SeriallyExecutedBrowserTestCase(unittest.TestCase):
  def __init__(self, methodName):
    super(SeriallyExecutedBrowserTestCase, self).__init__(methodName)
    self._private_methodname = methodName

  def shortName(self):
    """Returns the method name this test runs, without the package prefix."""
    return self._private_methodname

  @classmethod
  def Name(cls):
    return cls.__name__

  @classmethod
  def AddCommandlineArgs(cls, parser):
    pass

  @classmethod
  def SetUpProcess(cls):
    """ Set up testing logic before running the test case.
    This is guaranteed to be called only once for all the tests before the test
    suite runs.
    """
    finder_options = browser_test_context.GetCopy().finder_options
    cls._finder_options = finder_options

    # Set up logging based on the verbosity passed from the parent to
    # the child process.
    if finder_options.verbosity >= 2:
      logging.getLogger().setLevel(logging.DEBUG)
    elif finder_options.verbosity:
      logging.getLogger().setLevel(logging.INFO)
    else:
      logging.getLogger().setLevel(logging.WARNING)
    logging.basicConfig(format=DEFAULT_LOG_FORMAT)

    cls.platform = None
    cls.browser = None
    cls._browser_to_create = None
    cls._browser_options = None

  @classmethod
  def SetBrowserOptions(cls, browser_options):
    """Sets the browser option for the browser to create.

    Args:
      browser_options: Browser options object for the browser we want to test.
    """
    cls._browser_options = browser_options
    cls._browser_to_create = browser_finder.FindBrowser(browser_options)
    if not cls.platform:
      cls.platform = cls._browser_to_create.platform
      cls.platform.network_controller.InitializeIfNeeded()
    else:
      assert cls.platform == cls._browser_to_create.platform, (
          'All browser launches within same test suite must use browsers on '
          'the same platform')

  @classmethod
  def StartWPRServer(cls, archive_path=None, archive_bucket=None):
    """Start a webpage replay server.

    Args:
      archive_path: Path to the WPR file. If there is a corresponding sha1 file,
          this archive will be automatically downloaded from Google Storage.
      archive_bucket: The bucket to look for the WPR archive.
    """
    assert cls._browser_options, (
        'Browser options must be set with |SetBrowserOptions| prior to '
        'starting WPR')
    assert not cls.browser, 'WPR must be started prior to browser being started'

    cloud_storage.GetIfChanged(archive_path, archive_bucket)
    cls.platform.network_controller.Open(wpr_modes.WPR_REPLAY, [])
    cls.platform.network_controller.StartReplay(archive_path=archive_path)

  @classmethod
  def StopWPRServer(cls):
    cls.platform.network_controller.StopReplay()

  @classmethod
  def StartBrowser(cls):
    assert cls._browser_options, (
        'Browser options must be set with |SetBrowserOptions| prior to '
        'starting WPR')
    assert not cls.browser, 'Browser is started. Must close it first'

    cls.browser = cls._browser_to_create.Create(cls._browser_options)

  @classmethod
  def StopBrowser(cls):
    assert cls.browser, 'Browser is not started'
    cls.browser.Close()
    cls.browser = None

  @classmethod
  def TearDownProcess(cls):
    """ Tear down the testing logic after running the test cases.
    This is guaranteed to be called only once for all the tests after the test
    suite finishes running.
    """

    if cls.platform:
      cls.platform.StopAllLocalServers()
      cls.platform.network_controller.Close()
    if cls.browser:
      cls.StopBrowser()

  @classmethod
  def SetStaticServerDirs(cls, dirs_path):
    assert cls.platform
    assert isinstance(dirs_path, list)
    cls.platform.SetHTTPServerDirectories(dirs_path)

  @classmethod
  def UrlOfStaticFilePath(cls, file_path):
    return cls.platform.http_server.UrlOf(file_path)


def LoadAllTestsInModule(module):
  """ Load all tests & generated browser tests in a given module.

  This is supposed to be invoke in load_tests() method of your test modules that
  use browser_test_runner framework to discover & generate the tests to be
  picked up by the test runner. Here is the example of how your test module
  should looks like:

  ################## my_awesome_browser_tests.py  ################
  import sys

  from telemetry.testing import serially_executed_browser_test_case
  ...

  class TestSimpleBrowser(
      serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):
  ...
  ...

  def load_tests(loader, tests, pattern):
    return serially_executed_browser_test_case.LoadAllTestsInModule(
        sys.modules[__name__])
  #################################################################

  Args:
    module: the module which contains test cases classes.

  Returns:
    an instance of unittest.TestSuite, which contains all the tests & generated
    test cases to be run.
  """
  suite = unittest.TestSuite()
  test_context = browser_test_context.GetCopy()
  if not test_context:
    return suite
  for _, obj in inspect.getmembers(module):
    if (inspect.isclass(obj) and
        issubclass(obj, SeriallyExecutedBrowserTestCase)):
      # We bail out early if this class doesn't match the targeted
      # test_class in test_context to avoid calling GenerateTestCases
      # for tests that we don't intend to run. This is to avoid possible errors
      # in GenerateTestCases as the test class may define custom options in
      # the finder_options object, and hence would raise error if they can't
      # find their custom options in finder_options object.
      if test_context.test_class != obj:
        continue
      for test in GenerateTestCases(
          test_class=obj, finder_options=test_context.finder_options):
        if test.id() in test_context.test_case_ids_to_run:
          suite.addTest(test)
  return suite


def _GenerateTestMethod(based_method, args):
  return lambda self: based_method(self, *args)


_TEST_GENERATOR_PREFIX = 'GenerateTestCases_'
_INVALID_TEST_NAME_RE = re.compile(r'[^a-zA-Z0-9_]')

def _ValidateTestMethodname(test_name):
  assert not bool(_INVALID_TEST_NAME_RE.search(test_name))


def GenerateTestCases(test_class, finder_options):
  test_cases = []
  for name, method in inspect.getmembers(
      test_class, predicate=inspect.ismethod):
    if name.startswith('test'):
      # Do not allow method names starting with "test" in these
      # subclasses, to avoid collisions with Python's unit test runner.
      raise Exception('Name collision with Python\'s unittest runner: %s' %
                      name)
    elif name.startswith('Test'):
      # Pass these through for the time being. We may want to rethink
      # how they are handled in the future.
      test_cases.append(test_class(name))
    elif name.startswith(_TEST_GENERATOR_PREFIX):
      based_method_name = name[len(_TEST_GENERATOR_PREFIX):]
      assert hasattr(test_class, based_method_name), (
          '%s is specified but based method %s does not exist' %
          (name, based_method_name))
      based_method = getattr(test_class, based_method_name)
      for generated_test_name, args in method(finder_options):
        _ValidateTestMethodname(generated_test_name)
        setattr(test_class, generated_test_name, _GenerateTestMethod(
            based_method, args))
        test_cases.append(test_class(generated_test_name))
  return test_cases
