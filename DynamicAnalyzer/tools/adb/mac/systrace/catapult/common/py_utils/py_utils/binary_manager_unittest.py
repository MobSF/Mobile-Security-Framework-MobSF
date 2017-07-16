# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os

from pyfakefs import fake_filesystem_unittest
from dependency_manager import exceptions

from py_utils import binary_manager

class BinaryManagerTest(fake_filesystem_unittest.TestCase):
  # TODO(aiolos): disable cloud storage use during this test.

  def setUp(self):
    self.setUpPyfakefs()
    # pylint: disable=bad-continuation
    self.expected_dependencies = {
        'dep_1': {
          'cloud_storage_base_folder': 'dependencies/fake_config',
          'cloud_storage_bucket': 'chrome-tel',
          'file_info': {
            'linux_x86_64': {
              'cloud_storage_hash': '661ce936b3276f7ec3d687ab62be05b96d796f21',
              'download_path': 'bin/linux/x86_64/dep_1'
            },
            'mac_x86_64': {
              'cloud_storage_hash': 'c7b1bfc6399dc683058e88dac1ef0f877edea74b',
              'download_path': 'bin/mac/x86_64/dep_1'
            },
            'win_AMD64': {
              'cloud_storage_hash': 'ac4fee89a51662b9d920bce443c19b9b2929b198',
              'download_path': 'bin/win/AMD64/dep_1.exe'
            },
            'win_x86': {
              'cloud_storage_hash': 'e246e183553ea26967d7b323ea269e3357b9c837',
              'download_path': 'bin/win/x86/dep_1.exe'
            }
          }
        },
        'dep_2': {
          'cloud_storage_base_folder': 'dependencies/fake_config',
          'cloud_storage_bucket': 'chrome-tel',
          'file_info': {
            'linux_x86_64': {
              'cloud_storage_hash': '13a57efae9a680ac0f160b3567e02e81f4ac493c',
              'download_path': 'bin/linux/x86_64/dep_2',
              'local_paths': [
                  '../../example/location/linux/dep_2',
                  '../../example/location2/linux/dep_2'
              ]
            },
            'mac_x86_64': {
              'cloud_storage_hash': 'd10c0ddaa8586b20449e951216bee852fa0f8850',
              'download_path': 'bin/mac/x86_64/dep_2',
              'local_paths': [
                  '../../example/location/mac/dep_2',
                  '../../example/location2/mac/dep_2'
              ]
            },
            'win_AMD64': {
              'cloud_storage_hash': 'fd5b417f78c7f7d9192a98967058709ded1d399d',
              'download_path': 'bin/win/AMD64/dep_2.exe',
              'local_paths': [
                  '../../example/location/win64/dep_2',
                  '../../example/location2/win64/dep_2'
              ]
            },
            'win_x86': {
              'cloud_storage_hash': 'cf5c8fe920378ce30d057e76591d57f63fd31c1a',
              'download_path': 'bin/win/x86/dep_2.exe',
              'local_paths': [
                  '../../example/location/win32/dep_2',
                  '../../example/location2/win32/dep_2'
              ]
            },
            'android_k_x64': {
              'cloud_storage_hash': '09177be2fed00b44df0e777932828425440b23b3',
              'download_path': 'bin/android/x64/k/dep_2.apk',
              'local_paths': [
                  '../../example/location/android_x64/k/dep_2',
                  '../../example/location2/android_x64/k/dep_2'
              ]
            },
            'android_l_x64': {
              'cloud_storage_hash': '09177be2fed00b44df0e777932828425440b23b3',
              'download_path': 'bin/android/x64/l/dep_2.apk',
              'local_paths': [
                  '../../example/location/android_x64/l/dep_2',
                  '../../example/location2/android_x64/l/dep_2'
              ]
            },
            'android_k_x86': {
              'cloud_storage_hash': 'bcf02af039713a48b69b89bd7f0f9c81ed8183a4',
              'download_path': 'bin/android/x86/k/dep_2.apk',
              'local_paths': [
                  '../../example/location/android_x86/k/dep_2',
                  '../../example/location2/android_x86/k/dep_2'
              ]
            },
            'android_l_x86': {
              'cloud_storage_hash': '12a74cec071017ba11655b5740b8a58e2f52a219',
              'download_path': 'bin/android/x86/l/dep_2.apk',
              'local_paths': [
                  '../../example/location/android_x86/l/dep_2',
                  '../../example/location2/android_x86/l/dep_2'
              ]
            }
          }
        },
        'dep_3': {
          'file_info': {
            'linux_x86_64': {
              'local_paths': [
                  '../../example/location/linux/dep_3',
                  '../../example/location2/linux/dep_3'
              ]
            },
            'mac_x86_64': {
              'local_paths': [
                  '../../example/location/mac/dep_3',
                  '../../example/location2/mac/dep_3'
              ]
            },
            'win_AMD64': {
              'local_paths': [
                  '../../example/location/win64/dep_3',
                  '../../example/location2/win64/dep_3'
              ]
            },
            'win_x86': {
              'local_paths': [
                  '../../example/location/win32/dep_3',
                  '../../example/location2/win32/dep_3'
              ]
            }
          }
        }
    }
    # pylint: enable=bad-continuation
    fake_config = {
        'config_type': 'BaseConfig',
        'dependencies': self.expected_dependencies
    }

    self.base_config = os.path.join(os.path.dirname(__file__),
                                    'example_config.json')
    self.fs.CreateFile(self.base_config, contents=json.dumps(fake_config))
    linux_file = os.path.join(
        os.path.dirname(self.base_config),
        os.path.join('..', '..', 'example', 'location2', 'linux', 'dep_2'))
    android_file = os.path.join(
        os.path.dirname(self.base_config),
        '..', '..', 'example', 'location', 'android_x86', 'l', 'dep_2')
    self.expected_dep2_linux_file = os.path.abspath(linux_file)
    self.expected_dep2_android_file = os.path.abspath(android_file)
    self.fs.CreateFile(self.expected_dep2_linux_file)
    self.fs.CreateFile(self.expected_dep2_android_file)

  def tearDown(self):
    self.tearDownPyfakefs()

  def testInitializationNoConfig(self):
    with self.assertRaises(ValueError):
      binary_manager.BinaryManager(None)

  def testInitializationMissingConfig(self):
    with self.assertRaises(ValueError):
      binary_manager.BinaryManager(os.path.join('missing', 'path'))

  def testInitializationWithConfig(self):
    with self.assertRaises(ValueError):
      manager = binary_manager.BinaryManager(self.base_config)
    manager = binary_manager.BinaryManager([self.base_config])
    self.assertItemsEqual(self.expected_dependencies,
                          manager._dependency_manager._lookup_dict)

  def testSuccessfulFetchPathNoOsVersion(self):
    manager = binary_manager.BinaryManager([self.base_config])
    found_path = manager.FetchPath('dep_2', 'linux', 'x86_64')
    self.assertEqual(self.expected_dep2_linux_file, found_path)

  def testSuccessfulFetchPathOsVersion(self):
    manager = binary_manager.BinaryManager([self.base_config])
    found_path = manager.FetchPath('dep_2', 'android', 'x86', 'l')
    self.assertEqual(self.expected_dep2_android_file, found_path)

  def testSuccessfulFetchPathFallbackToNoOsVersion(self):
    manager = binary_manager.BinaryManager([self.base_config])
    found_path = manager.FetchPath('dep_2', 'linux', 'x86_64', 'fake_version')
    self.assertEqual(self.expected_dep2_linux_file, found_path)

  def testFailedFetchPathMissingDep(self):
    manager = binary_manager.BinaryManager([self.base_config])
    with self.assertRaises(exceptions.NoPathFoundError):
      manager.FetchPath('missing_dep', 'linux', 'x86_64')
    with self.assertRaises(exceptions.NoPathFoundError):
      manager.FetchPath('missing_dep', 'android', 'x86', 'l')
    with self.assertRaises(exceptions.NoPathFoundError):
      manager.FetchPath('dep_1', 'linux', 'bad_arch')
    with self.assertRaises(exceptions.NoPathFoundError):
      manager.FetchPath('dep_1', 'bad_os', 'x86')

  def testSuccessfulLocalPathNoOsVersion(self):
    manager = binary_manager.BinaryManager([self.base_config])
    found_path = manager.LocalPath('dep_2', 'linux', 'x86_64')
    self.assertEqual(self.expected_dep2_linux_file, found_path)

  def testSuccessfulLocalPathOsVersion(self):
    manager = binary_manager.BinaryManager([self.base_config])
    found_path = manager.LocalPath('dep_2', 'android', 'x86', 'l')
    self.assertEqual(self.expected_dep2_android_file, found_path)

