# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

import mock
from pyfakefs import fake_filesystem_unittest

from telemetry.core import android_platform
from telemetry.internal.backends.chrome import android_browser_finder
from telemetry.internal.platform import android_platform_backend
from telemetry.internal.util import binary_manager
from telemetry.testing import options_for_unittests


def FakeFetchPath(dependency, arch, os_name, os_version=None):
  return os.path.join(
      'dependency_dir', dependency, '%s_%s_%s.apk' % (
        os_name, os_version, arch))


class AndroidBrowserFinderTest(fake_filesystem_unittest.TestCase):
  def setUp(self):
    self.finder_options = options_for_unittests.GetCopy()
    # Mock out what's needed for testing with exact APKs
    self.setUpPyfakefs()
    self._fetch_path_patcher = mock.patch(
        'telemetry.internal.backends.chrome.android_browser_finder.binary_manager.FetchPath',  # pylint: disable=line-too-long
        FakeFetchPath)
    self._fetch_path_mock = self._fetch_path_patcher.start()
    self._get_package_name_patcher = mock.patch(
        'devil.android.apk_helper.GetPackageName')
    self._get_package_name_mock = self._get_package_name_patcher.start()
    self.fake_platform = mock.Mock(spec=android_platform.AndroidPlatform)
    self.fake_platform.CanLaunchApplication.return_value = True
    self.fake_platform._platform_backend = mock.create_autospec(
        android_platform_backend, spec_set=True)
    self.fake_platform.GetOSVersionName.return_value = 'L23ds5'
    self.fake_platform.GetArchName.return_value = 'armeabi-v7a'
    # The android_browser_finder converts the os version name to 'k' or 'l'
    self.expected_reference_build = FakeFetchPath(
        'chrome_stable', 'armeabi-v7a', 'android', 'l')

  def tearDown(self):
    self.tearDownPyfakefs()
    self._get_package_name_patcher.stop()
    self._fetch_path_patcher.stop()

  def testNoPlatformReturnsEmptyList(self):
    fake_platform = None
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, fake_platform)
    self.assertEqual([], possible_browsers)

  def testCanLaunchAlwaysTrueReturnsAllExceptExactAndReference(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    all_types = set(
        android_browser_finder.FindAllBrowserTypes(self.finder_options))
    expected_types = all_types - set(('exact', 'reference'))
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertEqual(
        expected_types,
        set([b.browser_type for b in possible_browsers]))

  def testCanLaunchAlwaysTrueReturnsAllExceptExact(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    self.fs.CreateFile(self.expected_reference_build)
    all_types = set(
        android_browser_finder.FindAllBrowserTypes(self.finder_options))
    expected_types = all_types - set(('exact',))
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertEqual(
        expected_types,
        set([b.browser_type for b in possible_browsers]))

  def testCanLaunchAlwaysTrueWithExactApkReturnsAll(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    self.fs.CreateFile(
        '/foo/ContentShell.apk')
    self.fs.CreateFile(self.expected_reference_build)
    self.finder_options.browser_executable = '/foo/ContentShell.apk'
    self._get_package_name_mock.return_value = 'org.chromium.content_shell_apk'

    expected_types = set(
        android_browser_finder.FindAllBrowserTypes(self.finder_options))
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertEqual(
        expected_types,
        set([b.browser_type for b in possible_browsers]))

  def testErrorWithUnknownExactApk(self):
    self.fs.CreateFile(
        '/foo/ContentShell.apk')
    self.finder_options.browser_executable = '/foo/ContentShell.apk'
    self._get_package_name_mock.return_value = 'org.unknown.app'

    self.assertRaises(Exception,
        android_browser_finder._FindAllPossibleBrowsers,
        self.finder_options, self.fake_platform)

  def testErrorWithNonExistantExactApk(self):
    self.finder_options.browser_executable = '/foo/ContentShell.apk'
    self._get_package_name_mock.return_value = 'org.chromium.content_shell_apk'

    self.assertRaises(Exception,
        android_browser_finder._FindAllPossibleBrowsers,
        self.finder_options, self.fake_platform)

  def testNoErrorWithUnrecognizedApkName(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    self.fs.CreateFile(
        '/foo/unknown.apk')
    self.finder_options.browser_executable = '/foo/unknown.apk'

    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertNotIn('exact', [b.browser_type for b in possible_browsers])

  def testCanLaunchExactWithUnrecognizedApkNameButKnownPackageName(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    self.fs.CreateFile(
        '/foo/MyFooBrowser.apk')
    self._get_package_name_mock.return_value = 'org.chromium.chrome'
    self.finder_options.browser_executable = '/foo/MyFooBrowser.apk'

    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertIn('exact', [b.browser_type for b in possible_browsers])

  def testNoErrorWithMissingReferenceBuild(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
      self.finder_options, self.fake_platform)
    self.assertNotIn('reference', [b.browser_type for b in possible_browsers])

  def testNoErrorWithReferenceBuildCloudStorageError(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    with mock.patch(
        'telemetry.internal.backends.chrome.android_browser_finder.binary_manager.FetchPath',  # pylint: disable=line-too-long
        side_effect=binary_manager.CloudStorageError):
      possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
        self.finder_options, self.fake_platform)
    self.assertNotIn('reference', [b.browser_type for b in possible_browsers])

  def testNoErrorWithReferenceBuildNoPathFoundError(self):
    if not self.finder_options.chrome_root:
      self.skipTest('--chrome-root is not specified, skip the test')
    self._fetch_path_mock.side_effect = binary_manager.NoPathFoundError
    possible_browsers = android_browser_finder._FindAllPossibleBrowsers(
      self.finder_options, self.fake_platform)
    self.assertNotIn('reference', [b.browser_type for b in possible_browsers])


class FakePossibleBrowser(object):
  def __init__(self, last_modification_time):
    self._last_modification_time = last_modification_time

  def last_modification_time(self):
    return self._last_modification_time


class SelectDefaultBrowserTest(unittest.TestCase):
  def testEmptyListGivesNone(self):
    self.assertIsNone(android_browser_finder.SelectDefaultBrowser([]))

  def testSinglePossibleReturnsSame(self):
    possible_browsers = [FakePossibleBrowser(last_modification_time=1)]
    self.assertIs(
      possible_browsers[0],
      android_browser_finder.SelectDefaultBrowser(possible_browsers))

  def testListGivesNewest(self):
    possible_browsers = [
        FakePossibleBrowser(last_modification_time=2),
        FakePossibleBrowser(last_modification_time=3),  # newest
        FakePossibleBrowser(last_modification_time=1),
        ]
    self.assertIs(
      possible_browsers[1],
      android_browser_finder.SelectDefaultBrowser(possible_browsers))
