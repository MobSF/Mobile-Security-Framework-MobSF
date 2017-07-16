#! /usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from devil import base_error
from devil import devil_env
from devil.android import apk_helper
from devil.utils import mock_calls

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


_MANIFEST_DUMP = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.abc" (Raw: "org.chromium.abc")
    A: split="random_split" (Raw: "random_split")
    E: uses-permission (line=2)
      A: android:name(0x01010003)="android.permission.INTERNET" (Raw: "android.permission.INTERNET")
    E: uses-permission (line=3)
      A: android:name(0x01010003)="android.permission.READ_EXTERNAL_STORAGE" (Raw: "android.permission.READ_EXTERNAL_STORAGE")
    E: uses-permission (line=4)
      A: android:name(0x01010003)="android.permission.ACCESS_FINE_LOCATION" (Raw: "android.permission.ACCESS_FINE_LOCATION")
    E: application (line=5)
      E: activity (line=6)
        A: android:name(0x01010003)="org.chromium.ActivityName" (Raw: "org.chromium.ActivityName")
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: service (line=7)
        A: android:name(0x01010001)="org.chromium.RandomService" (Raw: "org.chromium.RandomService")
        A: android:isolatedProcess(0x01010888)=(type 0x12)0xffffffff
    E: instrumentation (line=8)
      A: android:label(0x01010001)="abc" (Raw: "abc")
      A: android:name(0x01010003)="org.chromium.RandomJUnit4TestRunner" (Raw: "org.chromium.RandomJUnit4TestRunner")
      A: android:targetPackage(0x01010021)="org.chromium.random_package" (Raw:"org.chromium.random_pacakge")
      A: junit4=(type 0x12)0xffffffff (Raw: "true")
    E: instrumentation (line=9)
      A: android:label(0x01010001)="abc" (Raw: "abc")
      A: android:name(0x01010003)="org.chromium.RandomTestRunner" (Raw: "org.chromium.RandomTestRunner")
      A: android:targetPackage(0x01010021)="org.chromium.random_package" (Raw:"org.chromium.random_pacakge")
"""

_NO_ISOLATED_SERVICES = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.abc" (Raw: "org.chromium.abc")
    E: application (line=5)
      E: activity (line=6)
        A: android:name(0x01010003)="org.chromium.ActivityName" (Raw: "org.chromium.ActivityName")
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
      E: service (line=7)
        A: android:name(0x01010001)="org.chromium.RandomService" (Raw: "org.chromium.RandomService")
"""

_NO_SERVICES = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.abc" (Raw: "org.chromium.abc")
    E: application (line=5)
      E: activity (line=6)
        A: android:name(0x01010003)="org.chromium.ActivityName" (Raw: "org.chromium.ActivityName")
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
"""

_NO_APPLICATION = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.abc" (Raw: "org.chromium.abc")
"""

_SINGLE_INSTRUMENTATION_MANIFEST_DUMP = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.xyz" (Raw: "org.chromium.xyz")
    E: instrumentation (line=8)
      A: android:label(0x01010001)="xyz" (Raw: "xyz")
      A: android:name(0x01010003)="org.chromium.RandomTestRunner" (Raw: "org.chromium.RandomTestRunner")
      A: android:targetPackage(0x01010021)="org.chromium.random_package" (Raw:"org.chromium.random_pacakge")
"""

_SINGLE_J4_INSTRUMENTATION_MANIFEST_DUMP = """N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=1)
    A: package="org.chromium.xyz" (Raw: "org.chromium.xyz")
    E: instrumentation (line=8)
      A: android:label(0x01010001)="xyz" (Raw: "xyz")
      A: android:name(0x01010003)="org.chromium.RandomJ4TestRunner" (Raw: "org.chromium.RandomJ4TestRunner")
      A: android:targetPackage(0x01010021)="org.chromium.random_package" (Raw:"org.chromium.random_pacakge")
      A: junit4=(type 0x12)0xffffffff (Raw: "true")
"""


def _MockAaptDump(manifest_dump):
  return mock.patch(
      'devil.android.sdk.aapt.Dump',
      mock.Mock(side_effect=None, return_value=manifest_dump.split('\n')))

class ApkHelperTest(mock_calls.TestCase):

  def testGetInstrumentationName(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      with self.assertRaises(base_error.BaseError):
        helper.GetInstrumentationName()

  def testGetActivityName(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertEquals(
          helper.GetActivityName(), 'org.chromium.ActivityName')

  def testGetAllInstrumentations(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      all_instrumentations = helper.GetAllInstrumentations()
      self.assertEquals(len(all_instrumentations), 2)
      self.assertEquals(all_instrumentations[0]['android:name'],
                        'org.chromium.RandomJUnit4TestRunner')
      self.assertEquals(all_instrumentations[1]['android:name'],
                        'org.chromium.RandomTestRunner')

  def testGetPackageName(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertEquals(helper.GetPackageName(), 'org.chromium.abc')

  def testGetPermssions(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      all_permissions = helper.GetPermissions()
      self.assertEquals(len(all_permissions), 3)
      self.assertTrue('android.permission.INTERNET' in all_permissions)
      self.assertTrue(
          'android.permission.READ_EXTERNAL_STORAGE' in all_permissions)
      self.assertTrue(
          'android.permission.ACCESS_FINE_LOCATION' in all_permissions)

  def testGetSplitName(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertEquals(helper.GetSplitName(), 'random_split')

  def testHasIsolatedProcesses_noApplication(self):
    with _MockAaptDump(_NO_APPLICATION):
      helper = apk_helper.ApkHelper("")
      self.assertFalse(helper.HasIsolatedProcesses())

  def testHasIsolatedProcesses_noServices(self):
    with _MockAaptDump(_NO_SERVICES):
      helper = apk_helper.ApkHelper("")
      self.assertFalse(helper.HasIsolatedProcesses())

  def testHasIsolatedProcesses_oneNotIsolatedProcess(self):
    with _MockAaptDump(_NO_ISOLATED_SERVICES):
      helper = apk_helper.ApkHelper("")
      self.assertFalse(helper.HasIsolatedProcesses())

  def testHasIsolatedProcesses_oneIsolatedProcess(self):
    with _MockAaptDump(_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertTrue(helper.HasIsolatedProcesses())

  def testGetSingleInstrumentationName(self):
    with _MockAaptDump(_SINGLE_INSTRUMENTATION_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertEquals('org.chromium.RandomTestRunner',
                        helper.GetInstrumentationName())

  def testGetSingleJUnit4InstrumentationName(self):
    with _MockAaptDump(_SINGLE_J4_INSTRUMENTATION_MANIFEST_DUMP):
      helper = apk_helper.ApkHelper("")
      self.assertEquals('org.chromium.RandomJ4TestRunner',
                        helper.GetInstrumentationName())

