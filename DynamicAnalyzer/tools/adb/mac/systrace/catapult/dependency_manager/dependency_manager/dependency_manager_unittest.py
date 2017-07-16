# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=unused-argument

import mock

from pyfakefs import fake_filesystem_unittest
from py_utils import cloud_storage

import dependency_manager
from dependency_manager import exceptions


class DependencyManagerTest(fake_filesystem_unittest.TestCase):

  def setUp(self):
    self.lp_info012 = dependency_manager.LocalPathInfo(
        ['path0', 'path1', 'path2'])
    self.cloud_storage_info = dependency_manager.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'download_path', 'cs_remote_path')

    self.dep_info = dependency_manager.DependencyInfo(
        'dep', 'platform', 'config_file', local_path_info=self.lp_info012,
        cloud_storage_info=self.cloud_storage_info)
    self.setUpPyfakefs()

  def tearDown(self):
    self.tearDownPyfakefs()

  # TODO(nednguyen): add a test that construct
  # dependency_manager.DependencyManager from a list of DependencyInfo.
  def testErrorInit(self):
    with self.assertRaises(ValueError):
      dependency_manager.DependencyManager(None)
    with self.assertRaises(ValueError):
      dependency_manager.DependencyManager('config_file?')

  def testInitialUpdateDependencies(self):
    dep_manager = dependency_manager.DependencyManager([])

    # Empty BaseConfig.
    dep_manager._lookup_dict = {}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)
    base_config_mock.IterDependencyInfo.return_value = iter([])
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertFalse(dep_manager._lookup_dict)

    # One dependency/platform in a BaseConfig.
    dep_manager._lookup_dict = {}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)
    dep_info = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep = 'dependency'
    plat = 'platform'
    dep_info.dependency = dep
    dep_info.platform = plat
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info])
    expected_lookup_dict = {dep: {plat: dep_info}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info.Update.called)

    # One dependency multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = {}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)
    dep = 'dependency'
    plat1 = 'platform1'
    plat2 = 'platform2'
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep
    dep_info2.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info1,
                                                             dep_info2])
    expected_lookup_dict = {dep: {plat1: dep_info1,
                                  plat2: dep_info2}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)

    # Multiple dependencies, multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = {}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)
    dep1 = 'dependency1'
    dep2 = 'dependency2'
    plat1 = 'platform1'
    plat2 = 'platform2'
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep1
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep1
    dep_info2.platform = plat2
    dep_info3 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info3.dependency = dep2
    dep_info3.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter(
        [dep_info1, dep_info2, dep_info3])
    expected_lookup_dict = {dep1: {plat1: dep_info1,
                                   plat2: dep_info2},
                            dep2: {plat2: dep_info3}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)
    self.assertFalse(dep_info3.Update.called)

  def testFollowupUpdateDependenciesNoOverlap(self):
    dep_manager = dependency_manager.DependencyManager([])
    dep = 'dependency'
    dep1 = 'dependency1'
    dep2 = 'dependency2'
    dep3 = 'dependency3'
    plat1 = 'platform1'
    plat2 = 'platform2'
    plat3 = 'platform3'
    dep_info_a = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_a.dependency = dep1
    dep_info_a.platform = plat1
    dep_info_b = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_b.dependency = dep1
    dep_info_b.platform = plat2
    dep_info_c = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_c.dependency = dep
    dep_info_c.platform = plat1

    start_lookup_dict = {dep: {plat1: dep_info_a,
                               plat2: dep_info_b},
                         dep1: {plat1: dep_info_c}}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)

    # Empty BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    base_config_mock.IterDependencyInfo.return_value = iter([])
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(start_lookup_dict, dep_manager._lookup_dict)

    # One dependency/platform in a BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep_info = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info.dependency = dep3
    dep_info.platform = plat1
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c},
                            dep3: {plat3: dep_info}}

    dep_manager._UpdateDependencies(base_config_mock)
    self.assertItemsEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info.Update.called)
    self.assertFalse(dep_info_a.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    self.assertFalse(dep_info_c.Update.called)

    # One dependency multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep2
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep2
    dep_info2.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info1,
                                                             dep_info2])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c},
                            dep2: {plat1: dep_info1,
                                   plat2: dep_info2}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)
    self.assertFalse(dep_info_a.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    self.assertFalse(dep_info_c.Update.called)

    # Multiple dependencies, multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep1 = 'dependency1'
    plat1 = 'platform1'
    plat2 = 'platform2'
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep2
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep2
    dep_info2.platform = plat2
    dep_info3 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info3.dependency = dep3
    dep_info3.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter(
        [dep_info1, dep_info2, dep_info3])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c},
                            dep2: {plat1: dep_info1,
                                   plat2: dep_info2},
                            dep3: {plat2: dep_info3}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)
    self.assertFalse(dep_info3.Update.called)
    self.assertFalse(dep_info_a.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    self.assertFalse(dep_info_c.Update.called)

    # Ensure the testing data wasn't corrupted.
    self.assertEqual(start_lookup_dict,
                     {dep: {plat1: dep_info_a,
                            plat2: dep_info_b},
                      dep1: {plat1: dep_info_c}})

  def testFollowupUpdateDependenciesWithCollisions(self):
    dep_manager = dependency_manager.DependencyManager([])
    dep = 'dependency'
    dep1 = 'dependency1'
    dep2 = 'dependency2'
    plat1 = 'platform1'
    plat2 = 'platform2'
    dep_info_a = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_a.dependency = dep1
    dep_info_a.platform = plat1
    dep_info_b = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_b.dependency = dep1
    dep_info_b.platform = plat2
    dep_info_c = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info_c.dependency = dep
    dep_info_c.platform = plat1

    start_lookup_dict = {dep: {plat1: dep_info_a,
                               plat2: dep_info_b},
                         dep1: {plat1: dep_info_c}}
    base_config_mock = mock.MagicMock(spec=dependency_manager.BaseConfig)

    # One dependency/platform.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep_info = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info.dependency = dep
    dep_info.platform = plat1
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c}}

    dep_manager._UpdateDependencies(base_config_mock)
    self.assertItemsEqual(expected_lookup_dict, dep_manager._lookup_dict)
    dep_info_a.Update.assert_called_once_with(dep_info)
    self.assertFalse(dep_info.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    self.assertFalse(dep_info_c.Update.called)
    dep_info_a.reset_mock()
    dep_info_b.reset_mock()
    dep_info_c.reset_mock()

    # One dependency multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep1
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep2
    dep_info2.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info1,
                                                             dep_info2])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c},
                            dep2: {plat2: dep_info2}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)
    self.assertFalse(dep_info_a.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    dep_info_c.Update.assert_called_once_with(dep_info1)
    dep_info_a.reset_mock()
    dep_info_b.reset_mock()
    dep_info_c.reset_mock()

    # Multiple dependencies, multiple platforms in a BaseConfig.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep1 = 'dependency1'
    plat1 = 'platform1'
    plat2 = 'platform2'
    dep_info1 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info1.dependency = dep
    dep_info1.platform = plat1
    dep_info2 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info2.dependency = dep1
    dep_info2.platform = plat1
    dep_info3 = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info3.dependency = dep2
    dep_info3.platform = plat2
    base_config_mock.IterDependencyInfo.return_value = iter(
        [dep_info1, dep_info2, dep_info3])
    expected_lookup_dict = {dep: {plat1: dep_info_a,
                                  plat2: dep_info_b},
                            dep1: {plat1: dep_info_c},
                            dep2: {plat2: dep_info3}}
    dep_manager._UpdateDependencies(base_config_mock)
    self.assertEqual(expected_lookup_dict, dep_manager._lookup_dict)
    self.assertFalse(dep_info1.Update.called)
    self.assertFalse(dep_info2.Update.called)
    self.assertFalse(dep_info3.Update.called)
    self.assertFalse(dep_info_b.Update.called)
    dep_info_a.Update.assert_called_once_with(dep_info1)
    dep_info_c.Update.assert_called_once_with(dep_info2)

    # Collision error.
    dep_manager._lookup_dict = start_lookup_dict.copy()
    dep_info = mock.MagicMock(spec=dependency_manager.DependencyInfo)
    dep_info.dependency = dep
    dep_info.platform = plat1
    base_config_mock.IterDependencyInfo.return_value = iter([dep_info])
    dep_info_a.Update.side_effect = ValueError
    self.assertRaises(ValueError,
                      dep_manager._UpdateDependencies, base_config_mock)

    # Ensure the testing data wasn't corrupted.
    self.assertEqual(start_lookup_dict,
                     {dep: {plat1: dep_info_a,
                            plat2: dep_info_b},
                      dep1: {plat1: dep_info_c}})

  def testGetDependencyInfo(self):
    dep_manager = dependency_manager.DependencyManager([])
    self.assertFalse(dep_manager._lookup_dict)

    # No dependencies in the dependency manager.
    self.assertEqual(None, dep_manager._GetDependencyInfo('missing_dep',
                                                          'missing_plat'))

    dep_manager._lookup_dict = {'dep1': {'plat1': 'dep_info11',
                                         'plat2': 'dep_info12',
                                         'plat3': 'dep_info13'},
                                'dep2': {'plat1': 'dep_info11',
                                         'plat2': 'dep_info21',
                                         'plat3': 'dep_info23',
                                         'default': 'dep_info2d'},
                                'dep3': {'plat1': 'dep_info31',
                                         'plat2': 'dep_info32',
                                         'default': 'dep_info3d'}}
    # Dependency not in the dependency manager.
    self.assertEqual(None, dep_manager._GetDependencyInfo(
        'missing_dep', 'missing_plat'))
    # Dependency in the dependency manager, but not the platform. No default.
    self.assertEqual(None, dep_manager._GetDependencyInfo(
        'dep1', 'missing_plat'))
    # Dependency in the dependency manager, but not the platform, but a default
    # exists.
    self.assertEqual('dep_info2d', dep_manager._GetDependencyInfo(
        'dep2', 'missing_plat'))
    # Dependency and platform in the dependency manager. A default exists.
    self.assertEqual('dep_info23', dep_manager._GetDependencyInfo(
        'dep2', 'plat3'))
    # Dependency and platform in the dependency manager. No default exists.
    self.assertEqual('dep_info12', dep_manager._GetDependencyInfo(
        'dep1', 'plat2'))


















  @mock.patch(
      'dependency_manager.dependency_info.DependencyInfo.GetRemotePath')  # pylint: disable=line-too-long
  def testFetchPathUnititializedDependency(
      self, cs_path_mock):
    dep_manager = dependency_manager.DependencyManager([])
    self.assertFalse(cs_path_mock.call_args)
    cs_path = 'cs_path'
    cs_path_mock.return_value = cs_path

    # Empty lookup_dict
    with self.assertRaises(exceptions.NoPathFoundError):
      dep_manager.FetchPath('dep', 'plat_arch_x86')

    # Non-empty lookup dict that doesn't contain the dependency we're looking
    # for.
    dep_manager._lookup_dict = {'dep1': mock.MagicMock(),
                                'dep2': mock.MagicMock()}
    with self.assertRaises(exceptions.NoPathFoundError):
      dep_manager.FetchPath('dep', 'plat_arch_x86')

  @mock.patch('os.path')
  @mock.patch(
      'dependency_manager.DependencyManager._GetDependencyInfo')
  @mock.patch(
      'dependency_manager.dependency_info.DependencyInfo.GetRemotePath')  # pylint: disable=line-too-long
  def testFetchPathLocalFile(self, cs_path_mock, dep_info_mock, path_mock):
    dep_manager = dependency_manager.DependencyManager([])
    self.assertFalse(cs_path_mock.call_args)
    cs_path = 'cs_path'
    dep_info = self.dep_info
    cs_path_mock.return_value = cs_path
    # The DependencyInfo returned should be passed through to LocalPath.
    dep_info_mock.return_value = dep_info

    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path exists.
    dep_manager._lookup_dict = {'dep': {'platform' : self.dep_info},
                                'dep2': mock.MagicMock()}
    self.fs.CreateFile('path1')
    found_path = dep_manager.FetchPath('dep', 'platform')

    self.assertEqual('path1', found_path)
    self.assertFalse(cs_path_mock.call_args)


  @mock.patch(
      'dependency_manager.dependency_info.DependencyInfo.GetRemotePath')  # pylint: disable=line-too-long
  def testFetchPathRemoteFile(
      self, cs_path_mock):
    dep_manager = dependency_manager.DependencyManager([])
    self.assertFalse(cs_path_mock.call_args)
    cs_path = 'cs_path'
    def FakeCSPath():
      self.fs.CreateFile(cs_path)
      return cs_path
    cs_path_mock.side_effect = FakeCSPath

    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path doesn't exist, but cloud_storage_path is downloaded.
    dep_manager._lookup_dict = {'dep': {'platform' : self.dep_info,
                                        'plat1': mock.MagicMock()},
                                'dep2': {'plat2': mock.MagicMock()}}
    found_path = dep_manager.FetchPath('dep', 'platform')
    self.assertEqual(cs_path, found_path)


  @mock.patch(
      'dependency_manager.dependency_info.DependencyInfo.GetRemotePath')  # pylint: disable=line-too-long
  def testFetchPathError(
      self, cs_path_mock):
    dep_manager = dependency_manager.DependencyManager([])
    self.assertFalse(cs_path_mock.call_args)
    cs_path_mock.return_value = None
    dep_manager._lookup_dict = {'dep': {'platform' : self.dep_info,
                                        'plat1': mock.MagicMock()},
                                'dep2': {'plat2': mock.MagicMock()}}
    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path doesn't exist, and cloud_storage path wasn't successfully
    # found.
    self.assertRaises(exceptions.NoPathFoundError,
                      dep_manager.FetchPath, 'dep', 'platform')

    cs_path_mock.side_effect = cloud_storage.CredentialsError
    self.assertRaises(cloud_storage.CredentialsError,
                      dep_manager.FetchPath, 'dep', 'platform')

    cs_path_mock.side_effect = cloud_storage.CloudStorageError
    self.assertRaises(cloud_storage.CloudStorageError,
                      dep_manager.FetchPath, 'dep', 'platform')

    cs_path_mock.side_effect = cloud_storage.PermissionError
    self.assertRaises(cloud_storage.PermissionError,
                      dep_manager.FetchPath, 'dep', 'platform')

  def testLocalPath(self):
    dep_manager = dependency_manager.DependencyManager([])
    # Empty lookup_dict
    with self.assertRaises(exceptions.NoPathFoundError):
      dep_manager.LocalPath('dep', 'plat')

  def testLocalPathNoDependency(self):
    # Non-empty lookup dict that doesn't contain the dependency we're looking
    # for.
    dep_manager = dependency_manager.DependencyManager([])
    dep_manager._lookup_dict = {'dep1': mock.MagicMock(),
                                'dep2': mock.MagicMock()}
    with self.assertRaises(exceptions.NoPathFoundError):
      dep_manager.LocalPath('dep', 'plat')

  def testLocalPathExists(self):
    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path exists.
    dep_manager = dependency_manager.DependencyManager([])
    dep_manager._lookup_dict = {'dependency' : {'platform': self.dep_info},
                                'dep1': mock.MagicMock(),
                                'dep2': mock.MagicMock()}
    self.fs.CreateFile('path1')
    found_path = dep_manager.LocalPath('dependency', 'platform')

    self.assertEqual('path1', found_path)

  def testLocalPathMissingPaths(self):
    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path is found but doesn't exist.
    dep_manager = dependency_manager.DependencyManager([])
    dep_manager._lookup_dict = {'dependency' : {'platform': self.dep_info},
                                'dep1': mock.MagicMock(),
                                'dep2': mock.MagicMock()}
    self.assertRaises(exceptions.NoPathFoundError,
                      dep_manager.LocalPath, 'dependency', 'platform')

  def testLocalPathNoPaths(self):
    # Non-empty lookup dict that contains the dependency we're looking for.
    # Local path isn't found.
    dep_manager = dependency_manager.DependencyManager([])
    dep_info = dependency_manager.DependencyInfo(
        'dep', 'platform', 'config_file',
        cloud_storage_info=self.cloud_storage_info)
    dep_manager._lookup_dict = {'dependency' : {'platform': dep_info},
                                'dep1': mock.MagicMock(),
                                'dep2': mock.MagicMock()}
    self.assertRaises(exceptions.NoPathFoundError,
                      dep_manager.LocalPath, 'dependency', 'platform')

