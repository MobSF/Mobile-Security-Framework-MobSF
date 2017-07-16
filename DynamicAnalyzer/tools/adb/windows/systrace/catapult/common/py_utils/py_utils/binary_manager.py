# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

import dependency_manager


class BinaryManager(object):
  """ This class is effectively a subclass of dependency_manager, but uses a
      different number of arguments for FetchPath and LocalPath.
  """

  def __init__(self, config_files):
    if not config_files or type(config_files) != list:
      raise ValueError(
          'Must supply a list of config files to the BinaryManager')
    configs = [dependency_manager.BaseConfig(config) for config in config_files]
    self._dependency_manager = dependency_manager.DependencyManager(configs)

  def FetchPathWithVersion(self, binary_name, os_name, arch, os_version=None):
    """ Return a path to the executable for <binary_name>, or None if not found.

    Will attempt to download from cloud storage if needed.
    """
    return self._WrapDependencyManagerFunction(
        self._dependency_manager.FetchPathWithVersion, binary_name, os_name,
        arch, os_version)

  def FetchPath(self, binary_name, os_name, arch, os_version=None):
    """ Return a path to the executable for <binary_name>, or None if not found.

    Will attempt to download from cloud storage if needed.
    """
    return self._WrapDependencyManagerFunction(
        self._dependency_manager.FetchPath, binary_name, os_name, arch,
        os_version)

  def LocalPath(self, binary_name, os_name, arch, os_version=None):
    """ Return a local path to the given binary name, or None if not found.

    Will not download from cloud_storage.
    """
    return self._WrapDependencyManagerFunction(
        self._dependency_manager.LocalPath, binary_name, os_name, arch,
        os_version)

  def _WrapDependencyManagerFunction(
      self, function, binary_name, os_name, arch, os_version):
    platform = '%s_%s' % (os_name, arch)
    if os_version:
      try:
        versioned_platform = '%s_%s_%s' % (os_name, os_version, arch)
        return function(binary_name, versioned_platform)
      except dependency_manager.NoPathFoundError:
        logging.warning(
            'Cannot find path for %s on platform %s. Falling back to %s.',
            binary_name, versioned_platform, platform)
    return function(binary_name, platform)

