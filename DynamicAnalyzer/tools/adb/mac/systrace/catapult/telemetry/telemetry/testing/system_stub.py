# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides stubs for os, sys and subprocess for testing

This test allows one to test code that itself uses os, sys, and subprocess.
"""

import ntpath
import os
import posixpath
import re
import shlex
import sys


class Override(object):

  _overidden_modules = set()

  def __init__(self, base_module, module_list):
    self.cloud_storage = None
    self.open = None
    self.os = None
    self.perf_control = None
    self.raw_input = None
    self.subprocess = None
    self.sys = None
    self.thermal_throttle = None
    self.logging = None
    stubs = {'cloud_storage': CloudStorageModuleStub,
             'open': OpenFunctionStub,
             'os': OsModuleStub,
             'perf_control': PerfControlModuleStub,
             'raw_input': RawInputFunctionStub,
             'subprocess': SubprocessModuleStub,
             'sys': SysModuleStub,
             'thermal_throttle': ThermalThrottleModuleStub,
             'logging': LoggingStub,
    }
    self.adb_commands = None
    self.os = None
    self.subprocess = None
    self.sys = None

    assert base_module not in self._overidden_modules, (
        '%s is already overridden' % base_module.__name__)
    self._overidden_modules.add(base_module)
    self._base_module = base_module
    self._overrides = {}

    for module_name in module_list:
      self._overrides[module_name] = getattr(base_module, module_name, None)
      setattr(self, module_name, stubs[module_name]())
      setattr(base_module, module_name, getattr(self, module_name))

    if self.os and self.sys:
      self.os.path.sys = self.sys

  def __del__(self):
    assert not len(self._overrides)

  def Restore(self):
    for module_name, original_module in self._overrides.iteritems():
      if original_module is None:
        # This will happen when we override built-in functions, like open.
        # If we don't delete the attribute, we will shadow the built-in
        # function with an attribute set to None.
        delattr(self._base_module, module_name)
      else:
        setattr(self._base_module, module_name, original_module)
    self._overrides = {}
    self._overidden_modules.remove(self._base_module)
    self._base_module = None


class AdbDevice(object):

  def __init__(self):
    self.has_root = False
    self.needs_su = False
    self.shell_command_handlers = {}
    self.mock_content = []
    self.system_properties = {}
    if self.system_properties.get('ro.product.cpu.abi') == None:
      self.system_properties['ro.product.cpu.abi'] = 'armeabi-v7a'

  def HasRoot(self):
    return self.has_root

  def NeedsSU(self):
    return self.needs_su

  def RunShellCommand(self, args, **kwargs):
    del kwargs  # unused
    if isinstance(args, basestring):
      args = shlex.split(args)
    handler = self.shell_command_handlers[args[0]]
    return handler(args)

  def FileExists(self, _):
    return False

  def ReadFile(self, device_path, as_root=False):
    del device_path, as_root  # unused
    return self.mock_content

  def GetProp(self, property_name):
    return self.system_properties[property_name]

  def SetProp(self, property_name, property_value):
    self.system_properties[property_name] = property_value


class CloudStorageModuleStub(object):
  PUBLIC_BUCKET = 'chromium-telemetry'
  PARTNER_BUCKET = 'chrome-partner-telemetry'
  INTERNAL_BUCKET = 'chrome-telemetry'
  BUCKET_ALIASES = {
    'public': PUBLIC_BUCKET,
    'partner': PARTNER_BUCKET,
    'internal': INTERNAL_BUCKET,
  }

  # These are used to test for CloudStorage errors.
  INTERNAL_PERMISSION = 2
  PARTNER_PERMISSION = 1
  PUBLIC_PERMISSION = 0
  # Not logged in.
  CREDENTIALS_ERROR_PERMISSION = -1

  class NotFoundError(Exception):
    pass

  class CloudStorageError(Exception):
    pass

  class PermissionError(CloudStorageError):
    pass

  class CredentialsError(CloudStorageError):
    pass

  def __init__(self):
    self.default_remote_paths = {CloudStorageModuleStub.INTERNAL_BUCKET:{},
                                 CloudStorageModuleStub.PARTNER_BUCKET:{},
                                 CloudStorageModuleStub.PUBLIC_BUCKET:{}}
    self.remote_paths = self.default_remote_paths
    self.local_file_hashes = {}
    self.local_hash_files = {}
    self.permission_level = CloudStorageModuleStub.INTERNAL_PERMISSION
    self.downloaded_files = []

  def SetPermissionLevelForTesting(self, permission_level):
    self.permission_level = permission_level

  def CheckPermissionLevelForBucket(self, bucket):
    if bucket == CloudStorageModuleStub.PUBLIC_BUCKET:
      return
    elif (self.permission_level ==
          CloudStorageModuleStub.CREDENTIALS_ERROR_PERMISSION):
      raise CloudStorageModuleStub.CredentialsError()
    elif bucket == CloudStorageModuleStub.PARTNER_BUCKET:
      if self.permission_level < CloudStorageModuleStub.PARTNER_PERMISSION:
        raise CloudStorageModuleStub.PermissionError()
    elif bucket == CloudStorageModuleStub.INTERNAL_BUCKET:
      if self.permission_level < CloudStorageModuleStub.INTERNAL_PERMISSION:
        raise CloudStorageModuleStub.PermissionError()
    elif bucket not in self.remote_paths:
      raise CloudStorageModuleStub.NotFoundError()

  def SetRemotePathsForTesting(self, remote_path_dict=None):
    if not remote_path_dict:
      self.remote_paths = self.default_remote_paths
      return
    self.remote_paths = remote_path_dict

  def GetRemotePathsForTesting(self):
    if not self.remote_paths:
      self.remote_paths = self.default_remote_paths
    return self.remote_paths

  # Set a dictionary of data files and their "calculated" hashes.
  def SetCalculatedHashesForTesting(self, calculated_hash_dictionary):
    self.local_file_hashes = calculated_hash_dictionary

  def GetLocalDataFiles(self):
    return self.local_file_hashes.keys()

  # Set a dictionary of hash files and the hashes they should contain.
  def SetHashFileContentsForTesting(self, hash_file_dictionary):
    self.local_hash_files = hash_file_dictionary

  def GetLocalHashFiles(self):
    return self.local_hash_files.keys()

  def ChangeRemoteHashForTesting(self, bucket, remote_path, new_hash):
    self.remote_paths[bucket][remote_path] = new_hash

  def List(self, bucket):
    if not bucket or not bucket in self.remote_paths:
      bucket_error = ('Incorrect bucket specified, correct buckets:' +
                      str(self.remote_paths))
      raise CloudStorageModuleStub.CloudStorageError(bucket_error)
    CloudStorageModuleStub.CheckPermissionLevelForBucket(self, bucket)
    return list(self.remote_paths[bucket].keys())

  def Exists(self, bucket, remote_path):
    CloudStorageModuleStub.CheckPermissionLevelForBucket(self, bucket)
    return remote_path in self.remote_paths[bucket]

  def Insert(self, bucket, remote_path, local_path):
    CloudStorageModuleStub.CheckPermissionLevelForBucket(self, bucket)
    if not local_path in self.GetLocalDataFiles():
      file_path_error = 'Local file path does not exist'
      raise CloudStorageModuleStub.CloudStorageError(file_path_error)
    self.remote_paths[bucket][remote_path] = (
      CloudStorageModuleStub.CalculateHash(self, local_path))
    return remote_path

  def GetHelper(self, bucket, remote_path, local_path, only_if_changed):
    CloudStorageModuleStub.CheckPermissionLevelForBucket(self, bucket)
    if not remote_path in self.remote_paths[bucket]:
      if only_if_changed:
        return False
      raise CloudStorageModuleStub.NotFoundError('Remote file does not exist.')
    remote_hash = self.remote_paths[bucket][remote_path]
    local_hash = self.local_file_hashes[local_path]
    if only_if_changed and remote_hash == local_hash:
      return False
    self.downloaded_files.append(remote_path)
    self.local_file_hashes[local_path] = remote_hash
    self.local_hash_files[local_path + '.sha1'] = remote_hash
    return remote_hash

  def Get(self, bucket, remote_path, local_path):
    return CloudStorageModuleStub.GetHelper(self, bucket, remote_path,
                                            local_path, False)

  def GetIfChanged(self, local_path, bucket=None):
    remote_path = os.path.basename(local_path)
    if bucket:
      return CloudStorageModuleStub.GetHelper(self, bucket, remote_path,
                                              local_path, True)
    result = CloudStorageModuleStub.GetHelper(
        self, self.PUBLIC_BUCKET, remote_path, local_path, True)
    if not result:
      result = CloudStorageModuleStub.GetHelper(
          self, self.PARTNER_BUCKET, remote_path, local_path, True)
    if not result:
      result = CloudStorageModuleStub.GetHelper(
          self, self.INTERNAL_BUCKET, remote_path, local_path, True)
    return result

  def GetFilesInDirectoryIfChanged(self, directory, bucket):
    if os.path.dirname(directory) == directory: # If in the root dir.
      raise ValueError('Trying to serve root directory from HTTP server.')
    for dirpath, _, filenames in os.walk(directory):
      for filename in filenames:
        path, extension = os.path.splitext(
            os.path.join(dirpath, filename))
        if extension != '.sha1':
          continue
        self.GetIfChanged(path, bucket)

  def CalculateHash(self, file_path):
    return self.local_file_hashes[file_path]

  def ReadHash(self, hash_path):
    return self.local_hash_files[hash_path]


class LoggingStub(object):
  def __init__(self):
    self.warnings = []
    self.errors = []

  def info(self, msg, *args):
    pass

  def error(self, msg, *args):
    self.errors.append(msg % args)

  def warning(self, msg, *args):
    self.warnings.append(msg % args)

  def warn(self, msg, *args):
    self.warning(msg, *args)


class OpenFunctionStub(object):
  class FileStub(object):
    def __init__(self, data):
      self._data = data

    def __enter__(self):
      return self

    def __exit__(self, *args):
      pass

    def read(self, size=None):
      if size:
        return self._data[:size]
      else:
        return self._data

    def write(self, data):
      self._data.write(data)

    def close(self):
      pass

  def __init__(self):
    self.files = {}

  def __call__(self, name, *args, **kwargs):
    return OpenFunctionStub.FileStub(self.files[name])


class OsModuleStub(object):
  class OsEnvironModuleStub(object):
    def get(self, _):
      return None

  class OsPathModuleStub(object):
    def __init__(self, sys_module):
      self.sys = sys_module
      self.files = []
      self.dirs = []

    def exists(self, path):
      return path in self.files

    def isfile(self, path):
      return path in self.files

    def isdir(self, path):
      return path in self.dirs

    def join(self, *paths):
      def IsAbsolutePath(path):
        if self.sys.platform.startswith('win'):
          return re.match('[a-zA-Z]:\\\\', path)
        else:
          return path.startswith('/')

      # Per Python specification, if any component is an absolute path,
      # discard previous components.
      for index, path in reversed(list(enumerate(paths))):
        if IsAbsolutePath(path):
          paths = paths[index:]
          break

      if self.sys.platform.startswith('win'):
        tmp = os.path.join(*paths)
        return tmp.replace('/', '\\')
      else:
        tmp = os.path.join(*paths)
        return tmp.replace('\\', '/')

    def basename(self, path):
      if self.sys.platform.startswith('win'):
        return ntpath.basename(path)
      else:
        return posixpath.basename(path)

    @staticmethod
    def abspath(path):
      return os.path.abspath(path)

    @staticmethod
    def expanduser(path):
      return os.path.expanduser(path)

    @staticmethod
    def dirname(path):
      return os.path.dirname(path)

    @staticmethod
    def realpath(path):
      return os.path.realpath(path)

    @staticmethod
    def split(path):
      return os.path.split(path)

    @staticmethod
    def splitext(path):
      return os.path.splitext(path)

    @staticmethod
    def splitdrive(path):
      return os.path.splitdrive(path)

  X_OK = os.X_OK

  sep = os.sep
  pathsep = os.pathsep

  def __init__(self, sys_module=sys):
    self.path = OsModuleStub.OsPathModuleStub(sys_module)
    self.environ = OsModuleStub.OsEnvironModuleStub()
    self.display = ':0'
    self.local_app_data = None
    self.sys_path = None
    self.program_files = None
    self.program_files_x86 = None
    self.devnull = os.devnull
    self._directory = {}

  def access(self, path, _):
    return path in self.path.files

  def getenv(self, name, value=None):
    if name == 'DISPLAY':
      env = self.display
    elif name == 'LOCALAPPDATA':
      env = self.local_app_data
    elif name == 'PATH':
      env = self.sys_path
    elif name == 'PROGRAMFILES':
      env = self.program_files
    elif name == 'PROGRAMFILES(X86)':
      env = self.program_files_x86
    else:
      raise NotImplementedError('Unsupported getenv')
    return env if env else value

  def chdir(self, path):
    pass

  def walk(self, top):
    for dir_name in self._directory:
      yield top, dir_name, self._directory[dir_name]


class PerfControlModuleStub(object):
  class PerfControlStub(object):
    def __init__(self, adb):
      pass

  def __init__(self):
    self.PerfControl = PerfControlModuleStub.PerfControlStub


class RawInputFunctionStub(object):
  def __init__(self):
    self.input = ''

  def __call__(self, name, *args, **kwargs):
    return self.input


class SubprocessModuleStub(object):
  class PopenStub(object):
    def __init__(self):
      self.communicate_result = ('', '')
      self.returncode_result = 0

    def __call__(self, args, **kwargs):
      return self

    def communicate(self):
      return self.communicate_result

    @property
    def returncode(self):
      return self.returncode_result

  def __init__(self):
    self.Popen = SubprocessModuleStub.PopenStub()
    self.PIPE = None

  def call(self, *args, **kwargs):
    pass


class SysModuleStub(object):
  def __init__(self):
    self.platform = ''


class ThermalThrottleModuleStub(object):
  class ThermalThrottleStub(object):
    def __init__(self, adb):
      pass

  def __init__(self):
    self.ThermalThrottle = ThermalThrottleModuleStub.ThermalThrottleStub
