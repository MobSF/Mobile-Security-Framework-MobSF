# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import json
import logging
import os
import platform
import sys
import tempfile
import threading

CATAPULT_ROOT_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..'))
DEPENDENCY_MANAGER_PATH = os.path.join(
    CATAPULT_ROOT_PATH, 'dependency_manager')
PYMOCK_PATH = os.path.join(
    CATAPULT_ROOT_PATH, 'third_party', 'mock')


@contextlib.contextmanager
def SysPath(path):
  sys.path.append(path)
  yield
  if sys.path[-1] != path:
    sys.path.remove(path)
  else:
    sys.path.pop()

with SysPath(DEPENDENCY_MANAGER_PATH):
  import dependency_manager  # pylint: disable=import-error

_ANDROID_BUILD_TOOLS = {'aapt', 'dexdump', 'split-select'}

_DEVIL_DEFAULT_CONFIG = os.path.abspath(os.path.join(
    os.path.dirname(__file__), 'devil_dependencies.json'))

_LEGACY_ENVIRONMENT_VARIABLES = {
  'ADB_PATH': {
    'dependency_name': 'adb',
    'platform': 'linux2_x86_64',
  },
  'ANDROID_SDK_ROOT': {
    'dependency_name': 'android_sdk',
    'platform': 'linux2_x86_64',
  },
}


def EmptyConfig():
  return {
    'config_type': 'BaseConfig',
    'dependencies': {}
  }


def LocalConfigItem(dependency_name, dependency_platform, dependency_path):
  if isinstance(dependency_path, basestring):
    dependency_path = [dependency_path]
  return {
    dependency_name: {
      'file_info': {
        dependency_platform: {
          'local_paths': dependency_path
        },
      },
    },
  }


def _GetEnvironmentVariableConfig():
  env_config = EmptyConfig()
  path_config = (
      (os.environ.get(k), v)
      for k, v in _LEGACY_ENVIRONMENT_VARIABLES.iteritems())
  path_config = ((p, c) for p, c in path_config if p)
  for p, c in path_config:
    env_config['dependencies'].update(
        LocalConfigItem(c['dependency_name'], c['platform'], p))
  return env_config


class _Environment(object):

  def __init__(self):
    self._dm_init_lock = threading.Lock()
    self._dm = None
    self._logging_init_lock = threading.Lock()
    self._logging_initialized = False

  def Initialize(self, configs=None, config_files=None):
    """Initialize devil's environment from configuration files.

    This uses all configurations provided via |configs| and |config_files|
    to determine the locations of devil's dependencies. Configurations should
    all take the form described by py_utils.dependency_manager.BaseConfig.
    If no configurations are provided, a default one will be used if available.

    Args:
      configs: An optional list of dict configurations.
      config_files: An optional list of files to load
    """

    # Make sure we only initialize self._dm once.
    with self._dm_init_lock:
      if self._dm is None:
        if configs is None:
          configs = []

        env_config = _GetEnvironmentVariableConfig()
        if env_config:
          configs.insert(0, env_config)
        self._InitializeRecursive(
            configs=configs,
            config_files=config_files)
        assert self._dm is not None, 'Failed to create dependency manager.'

  def _InitializeRecursive(self, configs=None, config_files=None):
    # This recurses through configs to create temporary files for each and
    # take advantage of context managers to appropriately close those files.
    # TODO(jbudorick): Remove this recursion if/when dependency_manager
    # supports loading configurations directly from a dict.
    if configs:
      with tempfile.NamedTemporaryFile(delete=False) as next_config_file:
        try:
          next_config_file.write(json.dumps(configs[0]))
          next_config_file.close()
          self._InitializeRecursive(
              configs=configs[1:],
              config_files=[next_config_file.name] + (config_files or []))
        finally:
          if os.path.exists(next_config_file.name):
            os.remove(next_config_file.name)
    else:
      config_files = config_files or []
      if 'DEVIL_ENV_CONFIG' in os.environ:
        config_files.append(os.environ.get('DEVIL_ENV_CONFIG'))
      config_files.append(_DEVIL_DEFAULT_CONFIG)

      self._dm = dependency_manager.DependencyManager(
          [dependency_manager.BaseConfig(c) for c in config_files])

  def InitializeLogging(self, log_level, formatter=None, handler=None):
    if self._logging_initialized:
      return

    with self._logging_init_lock:
      if self._logging_initialized:
        return

      formatter = formatter or logging.Formatter(
          '%(threadName)-4s  %(message)s')
      handler = handler or logging.StreamHandler(sys.stdout)
      handler.setFormatter(formatter)

      devil_logger = logging.getLogger('devil')
      devil_logger.setLevel(log_level)
      devil_logger.propagate = False
      devil_logger.addHandler(handler)

      import py_utils.cloud_storage
      lock_logger = py_utils.cloud_storage.logger
      lock_logger.setLevel(log_level)
      lock_logger.propagate = False
      lock_logger.addHandler(handler)

      self._logging_initialized = True

  def FetchPath(self, dependency, arch=None, device=None):
    if self._dm is None:
      self.Initialize()
    if dependency in _ANDROID_BUILD_TOOLS:
      self.FetchPath('android_build_tools_libc++', arch=arch, device=device)
    return self._dm.FetchPath(dependency, GetPlatform(arch, device))

  def LocalPath(self, dependency, arch=None, device=None):
    if self._dm is None:
      self.Initialize()
    return self._dm.LocalPath(dependency, GetPlatform(arch, device))

  def PrefetchPaths(self, dependencies=None, arch=None, device=None):
    return self._dm.PrefetchPaths(
        GetPlatform(arch, device), dependencies=dependencies)


def GetPlatform(arch=None, device=None):
  if arch or device:
    return 'android_%s' % (arch or device.product_cpu_abi)
  return '%s_%s' % (sys.platform, platform.machine())


config = _Environment()

