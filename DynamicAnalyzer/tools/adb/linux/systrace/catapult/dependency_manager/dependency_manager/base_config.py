# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import os

from py_utils import cloud_storage
from dependency_manager import archive_info
from dependency_manager import cloud_storage_info
from dependency_manager import dependency_info
from dependency_manager import exceptions
from dependency_manager import local_path_info
from dependency_manager import uploader


class BaseConfig(object):
  """A basic config class for use with the DependencyManager.

  Initiated with a json file in the following format:

            {  "config_type": "BaseConfig",
               "dependencies": {
                 "dep_name1": {
                   "cloud_storage_base_folder": "base_folder1",
                   "cloud_storage_bucket": "bucket1",
                   "file_info": {
                     "platform1": {
                        "cloud_storage_hash": "hash_for_platform1",
                        "download_path": "download_path111",
                        "version_in_cs": "1.11.1.11."
                        "local_paths": ["local_path1110", "local_path1111"]
                      },
                      "platform2": {
                        "cloud_storage_hash": "hash_for_platform2",
                        "download_path": "download_path2",
                        "local_paths": ["local_path20", "local_path21"]
                      },
                      ...
                   }
                 },
                 "dependency_name_2": {
                    ...
                 },
                  ...
              }
            }

    Required fields: "dependencies" and "config_type".
                     Note that config_type must be "BaseConfig"

    Assumptions:
        "cloud_storage_base_folder" is a top level folder in the given
          "cloud_storage_bucket" where all of the dependency files are stored
          at "dependency_name"_"cloud_storage_hash".

        "download_path" and all paths in "local_paths" are relative to the
          config file's location.

        All or none of the following cloud storage related fields must be
          included in each platform dictionary:
          "cloud_storage_hash", "download_path", "cs_remote_path"

        "version_in_cs" is an optional cloud storage field, but is dependent
          on the above cloud storage related fields.


    Also note that platform names are often of the form os_architechture.
    Ex: "win_AMD64"

    More information on the fields can be found in dependencies_info.py
  """
  def __init__(self, file_path, writable=False):
    """ Initialize a BaseConfig for the DependencyManager.

    Args:
        writable: False: This config will be used to lookup information.
                  True: This config will be used to update information.

        file_path: Path to a file containing a json dictionary in the expected
                   json format for this config class. Base format expected:

                   { "config_type": config_type,
                     "dependencies": dependencies_dict }

                   config_type: must match the return value of GetConfigType.
                   dependencies: A dictionary with the information needed to
                       create dependency_info instances for the given
                       dependencies.

                   See dependency_info.py for more information.
    """
    self._config_path = file_path
    self._writable = writable
    self._pending_uploads = []
    if not self._config_path:
      raise ValueError('Must supply config file path.')
    if not os.path.exists(self._config_path):
      if not writable:
        raise exceptions.EmptyConfigError(file_path)
      self._config_data = {}
      self._WriteConfigToFile(self._config_path, dependencies=self._config_data)
    else:
      with open(file_path, 'r') as f:
        config_data = json.load(f)
      if not config_data:
        raise exceptions.EmptyConfigError(file_path)
      config_type = config_data.pop('config_type', None)
      if config_type != self.GetConfigType():
        raise ValueError(
            'Supplied config_type (%s) is not the expected type (%s) in file '
            '%s' % (config_type, self.GetConfigType(), file_path))
      self._config_data = config_data.get('dependencies', {})

  def IterDependencyInfo(self):
    """ Yields a DependencyInfo for each dependency/platform pair.

    Raises:
        ReadWriteError: If called when the config is writable.
        ValueError: If any of the dependencies contain partial information for
            downloading from cloud_storage. (See dependency_info.py)
    """
    if self._writable:
      raise exceptions.ReadWriteError(
          'Trying to read dependency info from a  writable config. File for '
          'config: %s' % self._config_path)
    base_path = os.path.dirname(self._config_path)
    for dependency in self._config_data:
      dependency_dict = self._config_data.get(dependency)
      platforms_dict = dependency_dict.get('file_info', {})
      for platform in platforms_dict:
        platform_info = platforms_dict.get(platform)

        local_info = None
        local_paths = platform_info.get('local_paths', [])
        if local_paths:
          paths = []
          for path in local_paths:
            path = self._FormatPath(path)
            paths.append(os.path.abspath(os.path.join(base_path, path)))
          local_info = local_path_info.LocalPathInfo(paths)

        cs_info = None
        cs_bucket = dependency_dict.get('cloud_storage_bucket')
        cs_base_folder = dependency_dict.get('cloud_storage_base_folder', '')
        download_path = platform_info.get('download_path')
        if download_path:
          download_path = self._FormatPath(download_path)
          download_path = os.path.abspath(
              os.path.join(base_path, download_path))

          cs_hash = platform_info.get('cloud_storage_hash')
          if not cs_hash:
            raise exceptions.ConfigError(
                'Dependency %s has cloud storage info on platform %s, but is '
                'missing a cloud storage hash.', dependency, platform)
          cs_remote_path = self._CloudStorageRemotePath(
              dependency, cs_hash, cs_base_folder)
          version_in_cs = platform_info.get('version_in_cs')

          zip_info = None
          path_within_archive = platform_info.get('path_within_archive')
          if path_within_archive:
            unzip_path = os.path.abspath(
                os.path.join(os.path.dirname(download_path),
                             '%s_%s_%s' % (dependency, platform, cs_hash)))
            zip_info = archive_info.ArchiveInfo(
                download_path, unzip_path, path_within_archive)

          cs_info = cloud_storage_info.CloudStorageInfo(
              cs_bucket, cs_hash, download_path, cs_remote_path,
              version_in_cs=version_in_cs, archive_info=zip_info)

        dep_info = dependency_info.DependencyInfo(
            dependency, platform, self._config_path,
            local_path_info=local_info, cloud_storage_info=cs_info)
        yield dep_info

  @classmethod
  def GetConfigType(cls):
    return 'BaseConfig'

  @property
  def config_path(self):
    return self._config_path

  def AddCloudStorageDependencyUpdateJob(
      self, dependency, platform, dependency_path, version=None,
      execute_job=True):
    """Update the file downloaded from cloud storage for a dependency/platform.

    Upload a new file to cloud storage for the given dependency and platform
    pair and update the cloud storage hash and the version for the given pair.

    Example usage:
      The following should update the default platform for 'dep_name':
          UpdateCloudStorageDependency('dep_name', 'default', 'path/to/file')

      The following should update both the mac and win platforms for 'dep_name',
      or neither if either update fails:
          UpdateCloudStorageDependency(
              'dep_name', 'mac_x86_64', 'path/to/mac/file', execute_job=False)
          UpdateCloudStorageDependency(
              'dep_name', 'win_AMD64', 'path/to/win/file', execute_job=False)
          ExecuteUpdateJobs()

    Args:
      dependency: The dependency to update.
      platform: The platform to update the dependency info for.
      dependency_path: Path to the new dependency to be used.
      version: Version of the updated dependency, for checking future updates
          against.
      execute_job: True if the config should be written to disk and the file
          should be uploaded to cloud storage after the update. False if
          multiple updates should be performed atomically. Must call
          ExecuteUpdateJobs after all non-executed jobs are added to complete
          the update.

    Raises:
      ReadWriteError: If the config was not initialized as writable, or if
          |execute_job| is True but the config has update jobs still pending
          execution.
      ValueError: If no information exists in the config for |dependency| on
          |platform|.
    """
    self._ValidateIsConfigUpdatable(
        execute_job=execute_job, dependency=dependency, platform=platform)
    cs_hash = cloud_storage.CalculateHash(dependency_path)
    if version:
      self._SetPlatformData(dependency, platform, 'version_in_cs', version)
    self._SetPlatformData(dependency, platform, 'cloud_storage_hash', cs_hash)

    cs_base_folder = self._GetPlatformData(
        dependency, platform, 'cloud_storage_base_folder')
    cs_bucket = self._GetPlatformData(
        dependency, platform, 'cloud_storage_bucket')
    cs_remote_path = self._CloudStorageRemotePath(
        dependency, cs_hash, cs_base_folder)
    self._pending_uploads.append(uploader.CloudStorageUploader(
        cs_bucket, cs_remote_path, dependency_path))
    if execute_job:
      self.ExecuteUpdateJobs()

  def ExecuteUpdateJobs(self, force=False):
    """Write all config changes to the config_path specified in __init__.

    Upload all files pending upload and then write the updated config to
    file. Attempt to remove all uploaded files on failure.

    Args:
      force: True if files should be uploaded to cloud storage even if a
          file already exists in the upload location.

    Returns:
      True: if the config was dirty and the upload succeeded.
      False: if the config was not dirty.

    Raises:
      CloudStorageUploadConflictError: If |force| is False and the potential
          upload location of a file already exists.
      CloudStorageError: If copying an existing file to the backup location
          or uploading a new file fails.
    """
    self._ValidateIsConfigUpdatable()
    if not self._IsDirty():
      logging.info('ExecuteUpdateJobs called on clean config')
      return False
    if not self._pending_uploads:
      logging.debug('No files needing upload.')
    else:
      try:
        for item_pending_upload in self._pending_uploads:
          item_pending_upload.Upload(force)
        self._WriteConfigToFile(self._config_path, self._config_data)
        self._pending_uploads = []
      except:
        # Attempt to rollback the update in any instance of failure, even user
        # interrupt via Ctrl+C; but don't consume the exception.
        logging.error('Update failed, attempting to roll it back.')
        for upload_item in reversed(self._pending_uploads):
          upload_item.Rollback()
        raise
    return True

  def GetVersion(self, dependency, platform):
    """Return the Version information for the given dependency."""
    return self._GetPlatformData(
        dependency, platform, data_type='version_in_cs')

  def _IsDirty(self):
    with open(self._config_path, 'r') as fstream:
      curr_config_data = json.load(fstream)
    curr_config_data = curr_config_data.get('dependencies', {})
    return self._config_data != curr_config_data

  def _SetPlatformData(self, dependency, platform, data_type, data):
    self._ValidateIsConfigWritable()
    dependency_dict = self._config_data.get(dependency, {})
    platform_dict = dependency_dict.get('file_info', {}).get(platform)
    if not platform_dict:
      raise ValueError('No platform data for platform %s on dependency %s' %
                       (platform, dependency))
    if (data_type == 'cloud_storage_bucket' or
        data_type == 'cloud_storage_base_folder'):
      self._config_data[dependency][data_type] = data
    else:
      self._config_data[dependency]['file_info'][platform][data_type] = data

  def _GetPlatformData(self, dependency, platform, data_type=None):
    dependency_dict = self._config_data.get(dependency, {})
    if not dependency_dict:
      raise ValueError('Dependency %s is not in config.' % dependency)
    platform_dict = dependency_dict.get('file_info', {}).get(platform)
    if not platform_dict:
      raise ValueError('No platform data for platform %s on dependency %s' %
                       (platform, dependency))
    if data_type:
      if (data_type == 'cloud_storage_bucket' or
          data_type == 'cloud_storage_base_folder'):
        return dependency_dict.get(data_type)
      return platform_dict.get(data_type)
    return platform_dict

  def _ValidateIsConfigUpdatable(
      self, execute_job=False, dependency=None, platform=None):
    self._ValidateIsConfigWritable()
    if self._IsDirty() and execute_job:
      raise exceptions.ReadWriteError(
          'A change has already been made to this config. Either call without'
          'using the execute_job option or first call ExecuteUpdateJobs().')
    if dependency and not self._config_data.get(dependency):
      raise ValueError('Cannot update information because dependency %s does '
                       'not exist.' % dependency)
    if platform and not self._GetPlatformData(dependency, platform):
      raise ValueError('No dependency info is available for the given '
                       'dependency: %s' % dependency)

  def _ValidateIsConfigWritable(self):
    if not self._writable:
      raise exceptions.ReadWriteError(
          'Trying to update the information from a read-only config. '
          'File for config: %s' % self._config_path)

  @staticmethod
  def _CloudStorageRemotePath(dependency, cs_hash, cs_base_folder):
    cs_remote_file = '%s_%s' % (dependency, cs_hash)
    cs_remote_path = cs_remote_file if not cs_base_folder else (
        '%s/%s' % (cs_base_folder, cs_remote_file))
    return cs_remote_path

  @classmethod
  def _FormatPath(cls, file_path):
    """ Format |file_path| for the current file system.

    We may be downloading files for another platform, so paths must be
    downloadable on the current system.
    """
    if not file_path:
      return file_path
    if os.path.sep != '\\':
      return file_path.replace('\\', os.path.sep)
    elif os.path.sep != '/':
      return file_path.replace('/', os.path.sep)
    return file_path

  @classmethod
  def _WriteConfigToFile(cls, file_path, dependencies=None):
    json_dict = cls._GetJsonDict(dependencies)
    file_dir = os.path.dirname(file_path)
    if not os.path.exists(file_dir):
      os.makedirs(file_dir)
    with open(file_path, 'w') as outfile:
      json.dump(
          json_dict, outfile, indent=2, sort_keys=True, separators=(',', ': '))
    return json_dict

  @classmethod
  def _GetJsonDict(cls, dependencies=None):
    dependencies = dependencies or {}
    json_dict = {'config_type': cls.GetConfigType(),
                 'dependencies': dependencies}
    return json_dict
