# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import dependency_manager

class DependencyInfoTest(unittest.TestCase):
  def testInitRequiredInfo(self):
    # Must have a dependency, platform and file_path.
    self.assertRaises(ValueError, dependency_manager.DependencyInfo,
                      None, None, None)
    self.assertRaises(ValueError, dependency_manager.DependencyInfo,
                      'dep', None, None)
    self.assertRaises(ValueError, dependency_manager.DependencyInfo,
                      None, 'plat', None)
    self.assertRaises(ValueError, dependency_manager.DependencyInfo,
                      None, None, 'config_path')
    # Empty DependencyInfo.
    empty_di = dependency_manager.DependencyInfo('dep', 'plat', 'config_path')
    self.assertEqual('dep', empty_di.dependency)
    self.assertEqual('plat', empty_di.platform)
    self.assertEqual(['config_path'], empty_di.config_paths)
    self.assertFalse(empty_di.has_local_path_info)
    self.assertFalse(empty_di.has_cloud_storage_info)

  def testInitLocalPaths(self):
    local_path_info = dependency_manager.LocalPathInfo(['path0', 'path1'])
    dep_info = dependency_manager.DependencyInfo(
        'dep', 'platform', 'config_path', local_path_info
        )
    self.assertEqual('dep', dep_info.dependency)
    self.assertEqual('platform', dep_info.platform)
    self.assertEqual(['config_path'], dep_info.config_paths)
    self.assertEqual(local_path_info, dep_info._local_path_info)
    self.assertFalse(dep_info.has_cloud_storage_info)

  def testInitCloudStorageInfo(self):
    cs_info = dependency_manager.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'dowload_path', 'cs_remote_path')
    dep_info = dependency_manager.DependencyInfo(
        'dep', 'platform', 'config_path', cloud_storage_info=cs_info)
    self.assertEqual('dep', dep_info.dependency)
    self.assertEqual('platform', dep_info.platform)
    self.assertEqual(['config_path'], dep_info.config_paths)
    self.assertFalse(dep_info.has_local_path_info)
    self.assertTrue(dep_info.has_cloud_storage_info)
    self.assertEqual(cs_info, dep_info._cloud_storage_info)

  def testInitAllInfo(self):
    cs_info = dependency_manager.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'dowload_path', 'cs_remote_path')
    dep_info = dependency_manager.DependencyInfo(
        'dep', 'platform', 'config_path', cloud_storage_info=cs_info)
    self.assertEqual('dep', dep_info.dependency)
    self.assertEqual('platform', dep_info.platform)
    self.assertEqual(['config_path'], dep_info.config_paths)
    self.assertFalse(dep_info.has_local_path_info)
    self.assertTrue(dep_info.has_cloud_storage_info)


  def testUpdateRequiredArgsConflicts(self):
    lp_info = dependency_manager.LocalPathInfo(['path0', 'path2'])
    dep_info1 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path1', local_path_info=lp_info)
    dep_info2 = dependency_manager.DependencyInfo(
        'dep1', 'platform2', 'config_path2', local_path_info=lp_info)
    dep_info3 = dependency_manager.DependencyInfo(
        'dep2', 'platform1', 'config_path3', local_path_info=lp_info)
    self.assertRaises(ValueError, dep_info1.Update, dep_info2)
    self.assertRaises(ValueError, dep_info1.Update, dep_info3)
    self.assertRaises(ValueError, dep_info3.Update, dep_info2)

  def testUpdateMinimumCloudStorageInfo(self):
    dep_info1 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path1')

    cs_info2 = dependency_manager.CloudStorageInfo(
        cs_bucket='cs_bucket2', cs_hash='cs_hash2',
        download_path='download_path2', cs_remote_path='cs_remote_path2')
    dep_info2 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path2', cloud_storage_info=cs_info2)

    dep_info3 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path3')

    cs_info4 = dependency_manager.CloudStorageInfo(
        cs_bucket='cs_bucket4', cs_hash='cs_hash4',
        download_path='download_path4', cs_remote_path='cs_remote_path4')
    dep_info4 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path4', cloud_storage_info=cs_info4)

    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1'], dep_info1.config_paths)

    dep_info1.Update(dep_info2)
    self.assertFalse(dep_info1.has_local_path_info)
    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1', 'config_path2'], dep_info1.config_paths)

    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)

    dep_info1.Update(dep_info3)
    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1', 'config_path2', 'config_path3'],
                     dep_info1.config_paths)
    self.assertFalse(dep_info1.has_local_path_info)
    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)

    self.assertRaises(ValueError, dep_info1.Update, dep_info4)

  def testUpdateMaxCloudStorageInfo(self):
    dep_info1 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path1')

    zip_info2 = dependency_manager.ArchiveInfo(
        'archive_path2', 'unzip_path2', 'path_withing_archive2')
    cs_info2 = dependency_manager.CloudStorageInfo(
        'cs_bucket2', 'cs_hash2', 'download_path2', 'cs_remote_path2',
        version_in_cs='2.1.1', archive_info=zip_info2)
    dep_info2 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path2', cloud_storage_info=cs_info2)

    dep_info3 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path3')

    zip_info4 = dependency_manager.ArchiveInfo(
        'archive_path4', 'unzip_path4', 'path_withing_archive4')
    cs_info4 = dependency_manager.CloudStorageInfo(
        'cs_bucket4', 'cs_hash4', 'download_path4', 'cs_remote_path4',
        version_in_cs='4.2.1', archive_info=zip_info4)
    dep_info4 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path4', cloud_storage_info=cs_info4)

    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1'], dep_info1.config_paths)

    dep_info1.Update(dep_info2)
    self.assertFalse(dep_info1.has_local_path_info)
    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1', 'config_path2'], dep_info1.config_paths)

    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)

    dep_info1.Update(dep_info3)
    self.assertEqual('dep1', dep_info1.dependency)
    self.assertEqual('platform1', dep_info1.platform)
    self.assertEqual(['config_path1', 'config_path2', 'config_path3'],
                     dep_info1.config_paths)
    self.assertFalse(dep_info1.has_local_path_info)
    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)

    self.assertRaises(ValueError, dep_info1.Update, dep_info4)

  def testUpdateAllInfo(self):
    lp_info1 = dependency_manager.LocalPathInfo(['path1'])
    dep_info1 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path1', local_path_info=lp_info1)
    cs_info2 = dependency_manager.CloudStorageInfo(
        cs_bucket='cs_bucket2', cs_hash='cs_hash2',
        download_path='download_path2', cs_remote_path='cs_remote_path2')
    lp_info2 = dependency_manager.LocalPathInfo(['path2'])
    dep_info2 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path2', local_path_info=lp_info2,
        cloud_storage_info=cs_info2)
    lp_info3 = dependency_manager.LocalPathInfo(['path3'])
    dep_info3 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path3', local_path_info=lp_info3)
    lp_info4 = dependency_manager.LocalPathInfo(['path4'])
    cs_info4 = dependency_manager.CloudStorageInfo(
        cs_bucket='cs_bucket4', cs_hash='cs_hash4',
        download_path='download_path4', cs_remote_path='cs_remote_path4')
    dep_info4 = dependency_manager.DependencyInfo(
        'dep1', 'platform1', 'config_path4', local_path_info=lp_info4,
        cloud_storage_info=cs_info4)

    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path1'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path2'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path3'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path4'))

    dep_info1.Update(dep_info2)
    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)
    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path1'))
    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path2'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path3'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path4'))

    dep_info1.Update(dep_info3)
    cs_info = dep_info1._cloud_storage_info
    self.assertEqual(cs_info, cs_info2)
    self.assertEqual('cs_bucket2', cs_info._cs_bucket)
    self.assertEqual('cs_hash2', cs_info._cs_hash)
    self.assertEqual('download_path2', cs_info._download_path)
    self.assertEqual('cs_remote_path2', cs_info._cs_remote_path)
    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path1'))
    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path2'))
    self.assertTrue(dep_info1._local_path_info.IsPathInLocalPaths('path3'))
    self.assertFalse(dep_info1._local_path_info.IsPathInLocalPaths('path4'))

    self.assertRaises(ValueError, dep_info1.Update, dep_info4)

