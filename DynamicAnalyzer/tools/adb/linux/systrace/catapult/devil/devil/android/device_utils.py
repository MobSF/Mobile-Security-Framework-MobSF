# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides a variety of device interactions based on adb.

Eventually, this will be based on adb_wrapper.
"""
# pylint: disable=unused-argument

import calendar
import collections
import itertools
import json
import logging
import multiprocessing
import os
import posixpath
import pprint
import re
import shutil
import stat
import tempfile
import time
import threading
import uuid
import zipfile

from devil import base_error
from devil import devil_env
from devil.utils import cmd_helper
from devil.android import apk_helper
from devil.android import device_signal
from devil.android import decorators
from devil.android import device_errors
from devil.android import device_temp_file
from devil.android import install_commands
from devil.android import logcat_monitor
from devil.android import md5sum
from devil.android.constants import chrome
from devil.android.sdk import adb_wrapper
from devil.android.sdk import gce_adb_wrapper
from devil.android.sdk import intent
from devil.android.sdk import keyevent
from devil.android.sdk import split_select
from devil.android.sdk import version_codes
from devil.utils import host_utils
from devil.utils import parallelizer
from devil.utils import reraiser_thread
from devil.utils import timeout_retry
from devil.utils import zip_utils

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30
_DEFAULT_RETRIES = 3

# A sentinel object for default values
# TODO(jbudorick,perezju): revisit how default values are handled by
# the timeout_retry decorators.
DEFAULT = object()

_RESTART_ADBD_SCRIPT = """
  trap '' HUP
  trap '' TERM
  trap '' PIPE
  function restart() {
    stop adbd
    start adbd
  }
  restart &
"""

# Not all permissions can be set.
_PERMISSIONS_BLACKLIST = [
    'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS',
    'android.permission.ACCESS_MOCK_LOCATION',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.ACCESS_NOTIFICATION_POLICY',
    'android.permission.ACCESS_WIFI_STATE',
    'android.permission.AUTHENTICATE_ACCOUNTS',
    'android.permission.BLUETOOTH',
    'android.permission.BLUETOOTH_ADMIN',
    'android.permission.BROADCAST_STICKY',
    'android.permission.CHANGE_NETWORK_STATE',
    'android.permission.CHANGE_WIFI_MULTICAST_STATE',
    'android.permission.CHANGE_WIFI_STATE',
    'android.permission.DISABLE_KEYGUARD',
    'android.permission.DOWNLOAD_WITHOUT_NOTIFICATION',
    'android.permission.EXPAND_STATUS_BAR',
    'android.permission.GET_PACKAGE_SIZE',
    'android.permission.INSTALL_SHORTCUT',
    'android.permission.INTERNET',
    'android.permission.KILL_BACKGROUND_PROCESSES',
    'android.permission.MANAGE_ACCOUNTS',
    'android.permission.MODIFY_AUDIO_SETTINGS',
    'android.permission.NFC',
    'android.permission.READ_SYNC_SETTINGS',
    'android.permission.READ_SYNC_STATS',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.RECORD_VIDEO',
    'android.permission.REORDER_TASKS',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.RUN_INSTRUMENTATION',
    'android.permission.SET_ALARM',
    'android.permission.SET_TIME_ZONE',
    'android.permission.SET_WALLPAPER',
    'android.permission.SET_WALLPAPER_HINTS',
    'android.permission.TRANSMIT_IR',
    'android.permission.USE_CREDENTIALS',
    'android.permission.USE_FINGERPRINT',
    'android.permission.VIBRATE',
    'android.permission.WAKE_LOCK',
    'android.permission.WRITE_SYNC_SETTINGS',
    'com.android.browser.permission.READ_HISTORY_BOOKMARKS',
    'com.android.browser.permission.WRITE_HISTORY_BOOKMARKS',
    'com.android.launcher.permission.INSTALL_SHORTCUT',
    'com.chrome.permission.DEVICE_EXTRAS',
    'com.google.android.apps.now.CURRENT_ACCOUNT_ACCESS',
    'com.google.android.c2dm.permission.RECEIVE',
    'com.google.android.providers.gsf.permission.READ_GSERVICES',
    'com.sec.enterprise.knox.MDM_CONTENT_PROVIDER',
]
for package_info in chrome.PACKAGE_INFO.itervalues():
  _PERMISSIONS_BLACKLIST.extend([
      '%s.permission.C2D_MESSAGE' % package_info.package,
      '%s.permission.READ_WRITE_BOOKMARK_FOLDERS' % package_info.package,
      '%s.TOS_ACKED' % package_info.package])

_CURRENT_FOCUS_CRASH_RE = re.compile(
    r'\s*mCurrentFocus.*Application (Error|Not Responding): (\S+)}')

_GETPROP_RE = re.compile(r'\[(.*?)\]: \[(.*?)\]')
_IPV4_ADDRESS_RE = re.compile(r'([0-9]{1,3}\.){3}[0-9]{1,3}\:[0-9]{4,5}')

# Regex to parse the long (-l) output of 'ls' command, c.f.
# https://github.com/landley/toybox/blob/master/toys/posix/ls.c#L446
_LONG_LS_OUTPUT_RE = re.compile(
    r'(?P<st_mode>[\w-]{10})\s+'                  # File permissions
    r'(?:(?P<st_nlink>\d+)\s+)?'                  # Number of links (optional)
    r'(?P<st_owner>\w+)\s+'                       # Name of owner
    r'(?P<st_group>\w+)\s+'                       # Group of owner
    r'(?:'                                        # Either ...
      r'(?P<st_rdev_major>\d+),\s+'                 # Device major, and
      r'(?P<st_rdev_minor>\d+)\s+'                  # Device minor
    r'|'                                          # .. or
      r'(?P<st_size>\d+)\s+'                        # Size in bytes
    r')?'                                         # .. or nothing
    r'(?P<st_mtime>\d{4}-\d\d-\d\d \d\d:\d\d)\s+' # Modification date/time
    r'(?P<filename>.+?)'                          # File name
    r'(?: -> (?P<symbolic_link_to>.+))?'          # Symbolic link (optional)
    r'$'                                          # End of string
)
_LS_DATE_FORMAT = '%Y-%m-%d %H:%M'
_FILE_MODE_RE = re.compile(r'[dbclps-](?:[r-][w-][xSs-]){2}[r-][w-][xTt-]$')
_FILE_MODE_KIND = {
    'd': stat.S_IFDIR, 'b': stat.S_IFBLK, 'c': stat.S_IFCHR,
    'l': stat.S_IFLNK, 'p': stat.S_IFIFO, 's': stat.S_IFSOCK,
    '-': stat.S_IFREG}
_FILE_MODE_PERMS = [
    stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
    stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
    stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH,
]
_FILE_MODE_SPECIAL = [
    ('s', stat.S_ISUID),
    ('s', stat.S_ISGID),
    ('t', stat.S_ISVTX),
]
_SELINUX_MODE = {
    'enforcing': True,
    'permissive': False,
    'disabled': None
}
# Some devices require different logic for checking if root is necessary
_SPECIAL_ROOT_DEVICE_LIST = [
    'marlin',
    'sailfish',
]


@decorators.WithExplicitTimeoutAndRetries(
    _DEFAULT_TIMEOUT, _DEFAULT_RETRIES)
def GetAVDs():
  """Returns a list of Android Virtual Devices.

  Returns:
    A list containing the configured AVDs.
  """
  lines = cmd_helper.GetCmdOutput([
      os.path.join(devil_env.config.LocalPath('android_sdk'),
                   'tools', 'android'),
      'list', 'avd']).splitlines()
  avds = []
  for line in lines:
    if 'Name:' not in line:
      continue
    key, value = (s.strip() for s in line.split(':', 1))
    if key == 'Name':
      avds.append(value)
  return avds


@decorators.WithExplicitTimeoutAndRetries(
    _DEFAULT_TIMEOUT, _DEFAULT_RETRIES)
def RestartServer():
  """Restarts the adb server.

  Raises:
    CommandFailedError if we fail to kill or restart the server.
  """
  def adb_killed():
    return not adb_wrapper.AdbWrapper.IsServerOnline()

  def adb_started():
    return adb_wrapper.AdbWrapper.IsServerOnline()

  adb_wrapper.AdbWrapper.KillServer()
  if not timeout_retry.WaitFor(adb_killed, wait_period=1, max_tries=5):
    # TODO(perezju): raise an exception after fixng http://crbug.com/442319
    logger.warning('Failed to kill adb server')
  adb_wrapper.AdbWrapper.StartServer()
  if not timeout_retry.WaitFor(adb_started, wait_period=1, max_tries=5):
    raise device_errors.CommandFailedError('Failed to start adb server')


def _ParseModeString(mode_str):
  """Parse a mode string, e.g. 'drwxrwxrwx', into a st_mode value.

  Effectively the reverse of |mode_to_string| in, e.g.:
  https://github.com/landley/toybox/blob/master/lib/lib.c#L896
  """
  if not _FILE_MODE_RE.match(mode_str):
    raise ValueError('Unexpected file mode %r', mode_str)
  mode = _FILE_MODE_KIND[mode_str[0]]
  for c, flag in zip(mode_str[1:], _FILE_MODE_PERMS):
    if c != '-' and c.islower():
      mode |= flag
  for c, (t, flag) in zip(mode_str[3::3], _FILE_MODE_SPECIAL):
    if c.lower() == t:
      mode |= flag
  return mode


def _GetTimeStamp():
  """Return a basic ISO 8601 time stamp with the current local time."""
  return time.strftime('%Y%m%dT%H%M%S', time.localtime())


def _JoinLines(lines):
  # makes sure that the last line is also terminated, and is more memory
  # efficient than first appending an end-line to each line and then joining
  # all of them together.
  return ''.join(s for line in lines for s in (line, '\n'))


def _IsGceInstance(serial):
  return _IPV4_ADDRESS_RE.match(serial)


def _CreateAdbWrapper(device):
  if _IsGceInstance(str(device)):
    return gce_adb_wrapper.GceAdbWrapper(str(device))
  else:
    if isinstance(device, adb_wrapper.AdbWrapper):
      return device
    else:
      return adb_wrapper.AdbWrapper(device)


def _FormatPartialOutputError(output):
  lines = output.splitlines() if isinstance(output, basestring) else output
  message = ['Partial output found:']
  if len(lines) > 11:
    message.extend('- %s' % line for line in lines[:5])
    message.extend('<snip>')
    message.extend('- %s' % line for line in lines[-5:])
  else:
    message.extend('- %s' % line for line in lines)
  return '\n'.join(message)


class DeviceUtils(object):

  _MAX_ADB_COMMAND_LENGTH = 512
  _MAX_ADB_OUTPUT_LENGTH = 32768
  _LAUNCHER_FOCUSED_RE = re.compile(
      r'\s*mCurrentFocus.*(Launcher|launcher).*')
  _VALID_SHELL_VARIABLE = re.compile('^[a-zA-Z_][a-zA-Z0-9_]*$')

  LOCAL_PROPERTIES_PATH = posixpath.join('/', 'data', 'local.prop')

  # Property in /data/local.prop that controls Java assertions.
  JAVA_ASSERT_PROPERTY = 'dalvik.vm.enableassertions'

  def __init__(self, device, enable_device_files_cache=False,
               default_timeout=_DEFAULT_TIMEOUT,
               default_retries=_DEFAULT_RETRIES):
    """DeviceUtils constructor.

    Args:
      device: Either a device serial, an existing AdbWrapper instance, or an
        an existing AndroidCommands instance.
      enable_device_files_cache: For PushChangedFiles(), cache checksums of
        pushed files rather than recomputing them on a subsequent call.
      default_timeout: An integer containing the default number of seconds to
        wait for an operation to complete if no explicit value is provided.
      default_retries: An integer containing the default number or times an
        operation should be retried on failure if no explicit value is provided.
    """
    self.adb = None
    if isinstance(device, basestring):
      self.adb = _CreateAdbWrapper(device)
    elif isinstance(device, adb_wrapper.AdbWrapper):
      self.adb = device
    else:
      raise ValueError('Unsupported device value: %r' % device)
    self._commands_installed = None
    self._default_timeout = default_timeout
    self._default_retries = default_retries
    self._enable_device_files_cache = enable_device_files_cache
    self._cache = {}
    self._client_caches = {}
    self._cache_lock = threading.RLock()
    assert hasattr(self, decorators.DEFAULT_TIMEOUT_ATTR)
    assert hasattr(self, decorators.DEFAULT_RETRIES_ATTR)

    self._ClearCache()

  @property
  def serial(self):
    """Returns the device serial."""
    return self.adb.GetDeviceSerial()

  def __eq__(self, other):
    """Checks whether |other| refers to the same device as |self|.

    Args:
      other: The object to compare to. This can be a basestring, an instance
        of adb_wrapper.AdbWrapper, or an instance of DeviceUtils.
    Returns:
      Whether |other| refers to the same device as |self|.
    """
    return self.serial == str(other)

  def __lt__(self, other):
    """Compares two instances of DeviceUtils.

    This merely compares their serial numbers.

    Args:
      other: The instance of DeviceUtils to compare to.
    Returns:
      Whether |self| is less than |other|.
    """
    return self.serial < other.serial

  def __str__(self):
    """Returns the device serial."""
    return self.serial

  @decorators.WithTimeoutAndRetriesFromInstance()
  def IsOnline(self, timeout=None, retries=None):
    """Checks whether the device is online.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if the device is online, False otherwise.

    Raises:
      CommandTimeoutError on timeout.
    """
    try:
      return self.adb.GetState() == 'device'
    except base_error.BaseError as exc:
      logger.info('Failed to get state: %s', exc)
      return False

  @decorators.WithTimeoutAndRetriesFromInstance()
  def HasRoot(self, timeout=None, retries=None):
    """Checks whether or not adbd has root privileges.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if adbd has root privileges, False otherwise.

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    try:
      if self.product_name in _SPECIAL_ROOT_DEVICE_LIST:
        return self.GetProp('service.adb.root') == '1'
      self.RunShellCommand(['ls', '/root'], check_return=True)
      return True
    except device_errors.AdbCommandFailedError:
      return False

  def NeedsSU(self, timeout=DEFAULT, retries=DEFAULT):
    """Checks whether 'su' is needed to access protected resources.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if 'su' is available on the device and is needed to to access
        protected resources; False otherwise if either 'su' is not available
        (e.g. because the device has a user build), or not needed (because adbd
        already has root privileges).

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    if 'needs_su' not in self._cache:
      cmd = '%s && ! ls /root' % self._Su('ls /root')
      if self.product_name in _SPECIAL_ROOT_DEVICE_LIST:
        if self.HasRoot():
          self._cache['needs_su'] = False
          return False
        cmd = 'which which && which su'
      try:
        self.RunShellCommand(cmd, shell=True, check_return=True,
            timeout=self._default_timeout if timeout is DEFAULT else timeout,
            retries=self._default_retries if retries is DEFAULT else retries)
        self._cache['needs_su'] = True
      except device_errors.AdbCommandFailedError:
        self._cache['needs_su'] = False
    return self._cache['needs_su']


  def _Su(self, command):
    if self.build_version_sdk >= version_codes.MARSHMALLOW:
      return 'su 0 %s' % command
    return 'su -c %s' % command

  @decorators.WithTimeoutAndRetriesFromInstance()
  def EnableRoot(self, timeout=None, retries=None):
    """Restarts adbd with root privileges.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if root could not be enabled.
      CommandTimeoutError on timeout.
    """
    if self.IsUserBuild():
      raise device_errors.CommandFailedError(
          'Cannot enable root in user builds.', str(self))
    if 'needs_su' in self._cache:
      del self._cache['needs_su']
    self.adb.Root()
    self.WaitUntilFullyBooted()

  @decorators.WithTimeoutAndRetriesFromInstance()
  def IsUserBuild(self, timeout=None, retries=None):
    """Checks whether or not the device is running a user build.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if the device is running a user build, False otherwise (i.e. if
        it's running a userdebug build).

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    return self.build_type == 'user'

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetExternalStoragePath(self, timeout=None, retries=None):
    """Get the device's path to its SD card.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The device's path to its SD card.

    Raises:
      CommandFailedError if the external storage path could not be determined.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    self._EnsureCacheInitialized()
    if not self._cache['external_storage']:
      raise device_errors.CommandFailedError('$EXTERNAL_STORAGE is not set',
                                             str(self))
    return self._cache['external_storage']

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetApplicationPaths(self, package, timeout=None, retries=None):
    """Get the paths of the installed apks on the device for the given package.

    Args:
      package: Name of the package.

    Returns:
      List of paths to the apks on the device for the given package.
    """
    return self._GetApplicationPathsInternal(package)

  def _GetApplicationPathsInternal(self, package, skip_cache=False):
    cached_result = self._cache['package_apk_paths'].get(package)
    if cached_result is not None and not skip_cache:
      if package in self._cache['package_apk_paths_to_verify']:
        self._cache['package_apk_paths_to_verify'].remove(package)
        # Don't verify an app that is not thought to be installed. We are
        # concerned only with apps we think are installed having been
        # uninstalled manually.
        if cached_result and not self.PathExists(cached_result):
          cached_result = None
          self._cache['package_apk_checksums'].pop(package, 0)
      if cached_result is not None:
        return list(cached_result)
    # 'pm path' is liable to incorrectly exit with a nonzero number starting
    # in Lollipop.
    # TODO(jbudorick): Check if this is fixed as new Android versions are
    # released to put an upper bound on this.
    should_check_return = (self.build_version_sdk < version_codes.LOLLIPOP)
    output = self.RunShellCommand(
        ['pm', 'path', package], check_return=should_check_return)
    apks = []
    for line in output:
      if not line.startswith('package:'):
        continue
      apks.append(line[len('package:'):])
    if not apks and output:
      raise device_errors.CommandFailedError(
          'pm path returned: %r' % '\n'.join(output), str(self))
    self._cache['package_apk_paths'][package] = list(apks)
    return apks

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetApplicationVersion(self, package, timeout=None, retries=None):
    """Get the version name of a package installed on the device.

    Args:
      package: Name of the package.

    Returns:
      A string with the version name or None if the package is not found
      on the device.
    """
    output = self.RunShellCommand(
        ['dumpsys', 'package', package], check_return=True)
    if not output:
      return None
    for line in output:
      line = line.strip()
      if line.startswith('versionName='):
        return line[len('versionName='):]
    raise device_errors.CommandFailedError(
        'Version name for %s not found on dumpsys output' % package, str(self))

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetApplicationDataDirectory(self, package, timeout=None, retries=None):
    """Get the data directory on the device for the given package.

    Args:
      package: Name of the package.

    Returns:
      The package's data directory.
    Raises:
      CommandFailedError if the package's data directory can't be found,
        whether because it's not installed or otherwise.
    """
    output = self._RunPipedShellCommand(
        'pm dump %s | grep dataDir=' % cmd_helper.SingleQuote(package))
    for line in output:
      _, _, dataDir = line.partition('dataDir=')
      if dataDir:
        return dataDir
    raise device_errors.CommandFailedError(
        'Could not find data directory for %s', package)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def WaitUntilFullyBooted(self, wifi=False, timeout=None, retries=None):
    """Wait for the device to fully boot.

    This means waiting for the device to boot, the package manager to be
    available, and the SD card to be ready. It can optionally mean waiting
    for wifi to come up, too.

    Args:
      wifi: A boolean indicating if we should wait for wifi to come up or not.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError if one of the component waits times out.
      DeviceUnreachableError if the device becomes unresponsive.
    """
    def sd_card_ready():
      try:
        self.RunShellCommand(['test', '-d', self.GetExternalStoragePath()],
                             check_return=True)
        return True
      except device_errors.AdbCommandFailedError:
        return False

    def pm_ready():
      try:
        return self._GetApplicationPathsInternal('android', skip_cache=True)
      except device_errors.CommandFailedError:
        return False

    def boot_completed():
      try:
        return self.GetProp('sys.boot_completed', cache=False) == '1'
      except device_errors.CommandFailedError:
        return False

    def wifi_enabled():
      return 'Wi-Fi is enabled' in self.RunShellCommand(['dumpsys', 'wifi'],
                                                        check_return=False)

    self.adb.WaitForDevice()
    timeout_retry.WaitFor(sd_card_ready)
    timeout_retry.WaitFor(pm_ready)
    timeout_retry.WaitFor(boot_completed)
    if wifi:
      timeout_retry.WaitFor(wifi_enabled)

  REBOOT_DEFAULT_TIMEOUT = 10 * _DEFAULT_TIMEOUT

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=REBOOT_DEFAULT_TIMEOUT)
  def Reboot(self, block=True, wifi=False, timeout=None, retries=None):
    """Reboot the device.

    Args:
      block: A boolean indicating if we should wait for the reboot to complete.
      wifi: A boolean indicating if we should wait for wifi to be enabled after
        the reboot. The option has no effect unless |block| is also True.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    def device_offline():
      return not self.IsOnline()

    self.adb.Reboot()
    self._ClearCache()
    timeout_retry.WaitFor(device_offline, wait_period=1)
    if block:
      self.WaitUntilFullyBooted(wifi=wifi)

  INSTALL_DEFAULT_TIMEOUT = 4 * _DEFAULT_TIMEOUT

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=INSTALL_DEFAULT_TIMEOUT)
  def Install(self, apk, allow_downgrade=False, reinstall=False,
              permissions=None, timeout=None, retries=None):
    """Install an APK.

    Noop if an identical APK is already installed.

    Args:
      apk: An ApkHelper instance or string containing the path to the APK.
      allow_downgrade: A boolean indicating if we should allow downgrades.
      reinstall: A boolean indicating if we should keep any existing app data.
      permissions: Set of permissions to set. If not set, finds permissions with
          apk helper. To set no permissions, pass [].
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if the installation fails.
      CommandTimeoutError if the installation times out.
      DeviceUnreachableError on missing device.
    """
    self._InstallInternal(apk, None, allow_downgrade=allow_downgrade,
                          reinstall=reinstall, permissions=permissions)

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=INSTALL_DEFAULT_TIMEOUT)
  def InstallSplitApk(self, base_apk, split_apks, allow_downgrade=False,
                      reinstall=False, allow_cached_props=False,
                      permissions=None, timeout=None, retries=None):
    """Install a split APK.

    Noop if all of the APK splits are already installed.

    Args:
      base_apk: An ApkHelper instance or string containing the path to the base
          APK.
      split_apks: A list of strings of paths of all of the APK splits.
      allow_downgrade: A boolean indicating if we should allow downgrades.
      reinstall: A boolean indicating if we should keep any existing app data.
      allow_cached_props: Whether to use cached values for device properties.
      permissions: Set of permissions to set. If not set, finds permissions with
          apk helper. To set no permissions, pass [].
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if the installation fails.
      CommandTimeoutError if the installation times out.
      DeviceUnreachableError on missing device.
      DeviceVersionError if device SDK is less than Android L.
    """
    self._InstallInternal(base_apk, split_apks, reinstall=reinstall,
                          allow_cached_props=allow_cached_props,
                          permissions=permissions,
                          allow_downgrade=allow_downgrade)

  def _InstallInternal(self, base_apk, split_apks, allow_downgrade=False,
                       reinstall=False, allow_cached_props=False,
                       permissions=None):
    if split_apks:
      self._CheckSdkLevel(version_codes.LOLLIPOP)

    base_apk = apk_helper.ToHelper(base_apk)

    all_apks = [base_apk.path]
    if split_apks:
      all_apks += split_select.SelectSplits(
        self, base_apk.path, split_apks, allow_cached_props=allow_cached_props)
      if len(all_apks) == 1:
        logger.warning('split-select did not select any from %s', split_apks)

    missing_apks = [apk for apk in all_apks if not os.path.exists(apk)]
    if missing_apks:
      raise device_errors.CommandFailedError(
          'Attempted to install non-existent apks: %s'
              % pprint.pformat(missing_apks))

    package_name = base_apk.GetPackageName()
    device_apk_paths = self._GetApplicationPathsInternal(package_name)

    apks_to_install = None
    host_checksums = None
    if not device_apk_paths:
      apks_to_install = all_apks
    elif len(device_apk_paths) > 1 and not split_apks:
      logger.warning(
          'Installing non-split APK when split APK was previously installed')
      apks_to_install = all_apks
    elif len(device_apk_paths) == 1 and split_apks:
      logger.warning(
          'Installing split APK when non-split APK was previously installed')
      apks_to_install = all_apks
    else:
      try:
        apks_to_install, host_checksums = (
            self._ComputeStaleApks(package_name, all_apks))
      except EnvironmentError as e:
        logger.warning('Error calculating md5: %s', e)
        apks_to_install, host_checksums = all_apks, None
      if apks_to_install and not reinstall:
        self.Uninstall(package_name)
        apks_to_install = all_apks

    if apks_to_install:
      # Assume that we won't know the resulting device state.
      self._cache['package_apk_paths'].pop(package_name, 0)
      self._cache['package_apk_checksums'].pop(package_name, 0)
      if split_apks:
        partial = package_name if len(apks_to_install) < len(all_apks) else None
        self.adb.InstallMultiple(
            apks_to_install, partial=partial, reinstall=reinstall,
            allow_downgrade=allow_downgrade)
      else:
        self.adb.Install(
            base_apk.path, reinstall=reinstall, allow_downgrade=allow_downgrade)
      if (permissions is None
          and self.build_version_sdk >= version_codes.MARSHMALLOW):
        permissions = base_apk.GetPermissions()
      self.GrantPermissions(package_name, permissions)
      # Upon success, we know the device checksums, but not their paths.
      if host_checksums is not None:
        self._cache['package_apk_checksums'][package_name] = host_checksums
    else:
      # Running adb install terminates running instances of the app, so to be
      # consistent, we explicitly terminate it when skipping the install.
      self.ForceStop(package_name)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def Uninstall(self, package_name, keep_data=False, timeout=None,
                retries=None):
    """Remove the app |package_name| from the device.

    This is a no-op if the app is not already installed.

    Args:
      package_name: The package to uninstall.
      keep_data: (optional) Whether to keep the data and cache directories.
      timeout: Timeout in seconds.
      retries: Number of retries.

    Raises:
      CommandFailedError if the uninstallation fails.
      CommandTimeoutError if the uninstallation times out.
      DeviceUnreachableError on missing device.
    """
    installed = self._GetApplicationPathsInternal(package_name)
    if not installed:
      return
    try:
      self.adb.Uninstall(package_name, keep_data)
      self._cache['package_apk_paths'][package_name] = []
      self._cache['package_apk_checksums'][package_name] = set()
    except:
      # Clear cache since we can't be sure of the state.
      self._cache['package_apk_paths'].pop(package_name, 0)
      self._cache['package_apk_checksums'].pop(package_name, 0)
      raise

  def _CheckSdkLevel(self, required_sdk_level):
    """Raises an exception if the device does not have the required SDK level.
    """
    if self.build_version_sdk < required_sdk_level:
      raise device_errors.DeviceVersionError(
          ('Requires SDK level %s, device is SDK level %s' %
           (required_sdk_level, self.build_version_sdk)),
           device_serial=self.serial)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def RunShellCommand(self, cmd, shell=False, check_return=False, cwd=None,
                      env=None, run_as=None, as_root=False, single_line=False,
                      large_output=False, raw_output=False, timeout=None,
                      retries=None):
    """Run an ADB shell command.

    The command to run |cmd| should be a sequence of program arguments
    (preferred) or a single string with a shell script to run.

    When |cmd| is a sequence, it is assumed to contain the name of the command
    to run followed by its arguments. In this case, arguments are passed to the
    command exactly as given, preventing any further processing by the shell.
    This allows callers to easily pass arguments with spaces or special
    characters without having to worry about quoting rules. Whenever possible,
    it is recomended to pass |cmd| as a sequence.

    When |cmd| is passed as a single string, |shell| should be set to True.
    The command will be interpreted and run by the shell on the device,
    allowing the use of shell features such as pipes, wildcards, or variables.
    Failing to set shell=True will issue a warning, but this will be changed
    to a hard failure in the future (see: catapult:#3242).

    This behaviour is consistent with that of command runners in cmd_helper as
    well as Python's own subprocess.Popen.

    TODO(perezju) Change the default of |check_return| to True when callers
      have switched to the new behaviour.

    Args:
      cmd: A sequence containing the command to run and its arguments, or a
        string with a shell script to run (should also set shell=True).
      shell: A boolean indicating whether shell features may be used in |cmd|.
      check_return: A boolean indicating whether or not the return code should
        be checked.
      cwd: The device directory in which the command should be run.
      env: The environment variables with which the command should be run.
      run_as: A string containing the package as which the command should be
        run.
      as_root: A boolean indicating whether the shell command should be run
        with root privileges.
      single_line: A boolean indicating if only a single line of output is
        expected.
      large_output: Uses a work-around for large shell command output. Without
        this large output will be truncated.
      raw_output: Whether to only return the raw output
          (no splitting into lines).
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      If single_line is False, the output of the command as a list of lines,
      otherwise, a string with the unique line of output emmited by the command
      (with the optional newline at the end stripped).

    Raises:
      AdbCommandFailedError if check_return is True and the exit code of
        the command run on the device is non-zero.
      CommandFailedError if single_line is True but the output contains two or
        more lines.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    def env_quote(key, value):
      if not DeviceUtils._VALID_SHELL_VARIABLE.match(key):
        raise KeyError('Invalid shell variable name %r' % key)
      # using double quotes here to allow interpolation of shell variables
      return '%s=%s' % (key, cmd_helper.DoubleQuote(value))

    def run(cmd):
      return self.adb.Shell(cmd)

    def handle_check_return(cmd):
      try:
        return run(cmd)
      except device_errors.AdbCommandFailedError as exc:
        if check_return:
          raise
        else:
          return exc.output

    def handle_large_command(cmd):
      if len(cmd) < self._MAX_ADB_COMMAND_LENGTH:
        return handle_check_return(cmd)
      else:
        with device_temp_file.DeviceTempFile(self.adb, suffix='.sh') as script:
          self._WriteFileWithPush(script.name, cmd)
          logger.info('Large shell command will be run from file: %s ...',
                      cmd[:self._MAX_ADB_COMMAND_LENGTH])
          return handle_check_return('sh %s' % script.name_quoted)

    def handle_large_output(cmd, large_output_mode):
      if large_output_mode:
        with device_temp_file.DeviceTempFile(self.adb) as large_output_file:
          cmd = '( %s )>%s' % (cmd, large_output_file.name)
          logger.debug('Large output mode enabled. Will write output to '
                       'device and read results from file.')
          handle_large_command(cmd)
          return self.ReadFile(large_output_file.name, force_pull=True)
      else:
        try:
          return handle_large_command(cmd)
        except device_errors.AdbCommandFailedError as exc:
          if exc.status is None:
            logger.error(_FormatPartialOutputError(exc.output))
            logger.warning('Attempting to run in large_output mode.')
            logger.warning('Use RunShellCommand(..., large_output=True) for '
                           'shell commands that expect a lot of output.')
            return handle_large_output(cmd, True)
          else:
            raise

    if isinstance(cmd, basestring):
      if not shell:
        logging.warning(
            'The command to run should preferably be passed as a sequence of'
            ' args. If shell features are needed (pipes, wildcards, variables)'
            ' clients should explicitly set shell=True.')
    else:
      cmd = ' '.join(cmd_helper.SingleQuote(s) for s in cmd)
    if env:
      env = ' '.join(env_quote(k, v) for k, v in env.iteritems())
      cmd = '%s %s' % (env, cmd)
    if cwd:
      cmd = 'cd %s && %s' % (cmd_helper.SingleQuote(cwd), cmd)
    if run_as:
      cmd = 'run-as %s sh -c %s' % (cmd_helper.SingleQuote(run_as),
                                    cmd_helper.SingleQuote(cmd))
    if as_root and self.NeedsSU():
      # "su -c sh -c" allows using shell features in |cmd|
      cmd = self._Su('sh -c %s' % cmd_helper.SingleQuote(cmd))

    output = handle_large_output(cmd, large_output)

    if raw_output:
      return output

    output = output.splitlines()
    if single_line:
      if not output:
        return ''
      elif len(output) == 1:
        return output[0]
      else:
        msg = 'one line of output was expected, but got: %s'
        raise device_errors.CommandFailedError(msg % output, str(self))
    else:
      return output

  def _RunPipedShellCommand(self, script, **kwargs):
    PIPESTATUS_LEADER = 'PIPESTATUS: '

    script += '; echo "%s${PIPESTATUS[@]}"' % PIPESTATUS_LEADER
    kwargs.update(shell=True, check_return=True)
    output = self.RunShellCommand(script, **kwargs)
    pipestatus_line = output[-1]

    if not pipestatus_line.startswith(PIPESTATUS_LEADER):
      logger.error('Pipe exit statuses of shell script missing.')
      raise device_errors.AdbShellCommandFailedError(
          script, output, status=None,
          device_serial=self.serial)

    output = output[:-1]
    statuses = [
        int(s) for s in pipestatus_line[len(PIPESTATUS_LEADER):].split()]
    if any(statuses):
      raise device_errors.AdbShellCommandFailedError(
          script, output, status=statuses,
          device_serial=self.serial)
    return output

  @decorators.WithTimeoutAndRetriesFromInstance()
  def KillAll(self, process_name, exact=False, signum=device_signal.SIGKILL,
              as_root=False, blocking=False, quiet=False,
              timeout=None, retries=None):
    """Kill all processes with the given name on the device.

    Args:
      process_name: A string containing the name of the process to kill.
      exact: A boolean indicating whether to kill all processes matching
             the string |process_name| exactly, or all of those which contain
             |process_name| as a substring. Defaults to False.
      signum: An integer containing the signal number to send to kill. Defaults
              to SIGKILL (9).
      as_root: A boolean indicating whether the kill should be executed with
               root privileges.
      blocking: A boolean indicating whether we should wait until all processes
                with the given |process_name| are dead.
      quiet: A boolean indicating whether to ignore the fact that no processes
             to kill were found.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The number of processes attempted to kill.

    Raises:
      CommandFailedError if no process was killed and |quiet| is False.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    procs_pids = self.GetPids(process_name)
    if exact:
      procs_pids = {process_name: procs_pids.get(process_name, [])}
    pids = set(itertools.chain(*procs_pids.values()))
    if not pids:
      if quiet:
        return 0
      else:
        raise device_errors.CommandFailedError(
            'No process "%s"' % process_name, str(self))

    logger.info(
        'KillAll(%r, ...) attempting to kill the following:', process_name)
    for name, ids in procs_pids.iteritems():
      for i in ids:
        logger.info('  %05s %s', str(i), name)

    cmd = ['kill', '-%d' % signum] + sorted(pids)
    self.RunShellCommand(cmd, as_root=as_root, check_return=True)

    def all_pids_killed():
      procs_pids_remain = self.GetPids(process_name)
      return not pids.intersection(itertools.chain(*procs_pids_remain.values()))

    if blocking:
      timeout_retry.WaitFor(all_pids_killed, wait_period=0.1)

    return len(pids)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def StartActivity(self, intent_obj, blocking=False, trace_file_name=None,
                    force_stop=False, timeout=None, retries=None):
    """Start package's activity on the device.

    Args:
      intent_obj: An Intent object to send.
      blocking: A boolean indicating whether we should wait for the activity to
                finish launching.
      trace_file_name: If present, a string that both indicates that we want to
                       profile the activity and contains the path to which the
                       trace should be saved.
      force_stop: A boolean indicating whether we should stop the activity
                  before starting it.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if the activity could not be started.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    cmd = ['am', 'start']
    if blocking:
      cmd.append('-W')
    if trace_file_name:
      cmd.extend(['--start-profiler', trace_file_name])
    if force_stop:
      cmd.append('-S')
    cmd.extend(intent_obj.am_args)
    for line in self.RunShellCommand(cmd, check_return=True):
      if line.startswith('Error:'):
        raise device_errors.CommandFailedError(line, str(self))

  @decorators.WithTimeoutAndRetriesFromInstance()
  def StartInstrumentation(self, component, finish=True, raw=False,
                           extras=None, timeout=None, retries=None):
    if extras is None:
      extras = {}

    cmd = ['am', 'instrument']
    if finish:
      cmd.append('-w')
    if raw:
      cmd.append('-r')
    for k, v in extras.iteritems():
      cmd.extend(['-e', str(k), str(v)])
    cmd.append(component)

    # Store the package name in a shell variable to help the command stay under
    # the _MAX_ADB_COMMAND_LENGTH limit.
    package = component.split('/')[0]
    shell_snippet = 'p=%s;%s' % (package,
                                 cmd_helper.ShrinkToSnippet(cmd, 'p', package))
    return self.RunShellCommand(shell_snippet, shell=True, check_return=True,
                                large_output=True)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def BroadcastIntent(self, intent_obj, timeout=None, retries=None):
    """Send a broadcast intent.

    Args:
      intent: An Intent to broadcast.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    cmd = ['am', 'broadcast'] + intent_obj.am_args
    self.RunShellCommand(cmd, check_return=True)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GoHome(self, timeout=None, retries=None):
    """Return to the home screen and obtain launcher focus.

    This command launches the home screen and attempts to obtain
    launcher focus until the timeout is reached.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    def is_launcher_focused():
      output = self.RunShellCommand(['dumpsys', 'window', 'windows'],
                                    check_return=True, large_output=True)
      return any(self._LAUNCHER_FOCUSED_RE.match(l) for l in output)

    def dismiss_popups():
      # There is a dialog present; attempt to get rid of it.
      # Not all dialogs can be dismissed with back.
      self.SendKeyEvent(keyevent.KEYCODE_ENTER)
      self.SendKeyEvent(keyevent.KEYCODE_BACK)
      return is_launcher_focused()

    # If Home is already focused, return early to avoid unnecessary work.
    if is_launcher_focused():
      return

    self.StartActivity(
        intent.Intent(action='android.intent.action.MAIN',
                      category='android.intent.category.HOME'),
        blocking=True)

    if not is_launcher_focused():
      timeout_retry.WaitFor(dismiss_popups, wait_period=1)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def ForceStop(self, package, timeout=None, retries=None):
    """Close the application.

    Args:
      package: A string containing the name of the package to stop.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    cmd = 'p=%s;if [[ "$(ps)" = *$p* ]]; then am force-stop $p; fi'
    self.RunShellCommand(cmd % package, shell=True, check_return=True)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def ClearApplicationState(
      self, package, permissions=None, timeout=None, retries=None):
    """Clear all state for the given package.

    Args:
      package: A string containing the name of the package to stop.
      permissions: List of permissions to set after clearing data.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    # Check that the package exists before clearing it for android builds below
    # JB MR2. Necessary because calling pm clear on a package that doesn't exist
    # may never return.
    if ((self.build_version_sdk >= version_codes.JELLY_BEAN_MR2)
        or self._GetApplicationPathsInternal(package)):
      self.RunShellCommand(['pm', 'clear', package], check_return=True)
      self.GrantPermissions(package, permissions)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def SendKeyEvent(self, keycode, timeout=None, retries=None):
    """Sends a keycode to the device.

    See the devil.android.sdk.keyevent module for suitable keycode values.

    Args:
      keycode: A integer keycode to send to the device.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    self.RunShellCommand(['input', 'keyevent', format(keycode, 'd')],
                         check_return=True)

  PUSH_CHANGED_FILES_DEFAULT_TIMEOUT = 10 * _DEFAULT_TIMEOUT

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=PUSH_CHANGED_FILES_DEFAULT_TIMEOUT)
  def PushChangedFiles(self, host_device_tuples, timeout=None,
                       retries=None, delete_device_stale=False):
    """Push files to the device, skipping files that don't need updating.

    When a directory is pushed, it is traversed recursively on the host and
    all files in it are pushed to the device as needed.
    Additionally, if delete_device_stale option is True,
    files that exist on the device but don't exist on the host are deleted.

    Args:
      host_device_tuples: A list of (host_path, device_path) tuples, where
        |host_path| is an absolute path of a file or directory on the host
        that should be minimially pushed to the device, and |device_path| is
        an absolute path of the destination on the device.
      timeout: timeout in seconds
      retries: number of retries
      delete_device_stale: option to delete stale files on device

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """

    all_changed_files = []
    all_stale_files = []
    missing_dirs = []
    cache_commit_funcs = []
    for h, d in host_device_tuples:
      assert os.path.isabs(h) and posixpath.isabs(d)
      h = os.path.realpath(h)
      changed_files, up_to_date_files, stale_files, cache_commit_func = (
          self._GetChangedAndStaleFiles(h, d, delete_device_stale))
      all_changed_files += changed_files
      all_stale_files += stale_files
      cache_commit_funcs.append(cache_commit_func)
      if changed_files and not up_to_date_files and not stale_files:
        if os.path.isdir(h):
          missing_dirs.append(d)
        else:
          missing_dirs.append(posixpath.dirname(d))

    if delete_device_stale and all_stale_files:
      self.RunShellCommand(['rm', '-f'] + all_stale_files, check_return=True)

    if all_changed_files:
      if missing_dirs:
        self.RunShellCommand(['mkdir', '-p'] + missing_dirs, check_return=True)
      self._PushFilesImpl(host_device_tuples, all_changed_files)
    for func in cache_commit_funcs:
      func()

  def _GetChangedAndStaleFiles(self, host_path, device_path, track_stale=False):
    """Get files to push and delete

    Args:
      host_path: an absolute path of a file or directory on the host
      device_path: an absolute path of a file or directory on the device
      track_stale: whether to bother looking for stale files (slower)

    Returns:
      a four-element tuple
      1st element: a list of (host_files_path, device_files_path) tuples to push
      2nd element: a list of host_files_path that are up-to-date
      3rd element: a list of stale files under device_path, or [] when
        track_stale == False
      4th element: a cache commit function.
    """
    try:
      # Length calculations below assume no trailing /.
      host_path = host_path.rstrip('/')
      device_path = device_path.rstrip('/')

      specific_device_paths = [device_path]
      ignore_other_files = not track_stale and os.path.isdir(host_path)
      if ignore_other_files:
        specific_device_paths = []
        for root, _, filenames in os.walk(host_path):
          relative_dir = root[len(host_path) + 1:]
          specific_device_paths.extend(
              posixpath.join(device_path, relative_dir, f) for f in filenames)

      def calculate_host_checksums():
        return md5sum.CalculateHostMd5Sums([host_path])

      def calculate_device_checksums():
        if self._enable_device_files_cache:
          cache_entry = self._cache['device_path_checksums'].get(device_path)
          if cache_entry and cache_entry[0] == ignore_other_files:
            return dict(cache_entry[1])

        sums = md5sum.CalculateDeviceMd5Sums(specific_device_paths, self)

        cache_entry = [ignore_other_files, sums]
        self._cache['device_path_checksums'][device_path] = cache_entry
        return dict(sums)

      host_checksums, device_checksums = reraiser_thread.RunAsync((
          calculate_host_checksums,
          calculate_device_checksums))
    except EnvironmentError as e:
      logger.warning('Error calculating md5: %s', e)
      return ([(host_path, device_path)], [], [], lambda: 0)

    to_push = []
    up_to_date = []
    to_delete = []
    if os.path.isfile(host_path):
      host_checksum = host_checksums.get(host_path)
      device_checksum = device_checksums.get(device_path)
      if host_checksum == device_checksum:
        up_to_date.append(host_path)
      else:
        to_push.append((host_path, device_path))
    else:
      for host_abs_path, host_checksum in host_checksums.iteritems():
        device_abs_path = posixpath.join(
            device_path, os.path.relpath(host_abs_path, host_path))
        device_checksum = device_checksums.pop(device_abs_path, None)
        if device_checksum == host_checksum:
          up_to_date.append(host_abs_path)
        else:
          to_push.append((host_abs_path, device_abs_path))
      to_delete = device_checksums.keys()

    def cache_commit_func():
      new_sums = {posixpath.join(device_path, path[len(host_path) + 1:]): val
                  for path, val in host_checksums.iteritems()}
      cache_entry = [ignore_other_files, new_sums]
      self._cache['device_path_checksums'][device_path] = cache_entry

    return (to_push, up_to_date, to_delete, cache_commit_func)

  def _ComputeDeviceChecksumsForApks(self, package_name):
    ret = self._cache['package_apk_checksums'].get(package_name)
    if ret is None:
      device_paths = self._GetApplicationPathsInternal(package_name)
      file_to_checksums = md5sum.CalculateDeviceMd5Sums(device_paths, self)
      ret = set(file_to_checksums.values())
      self._cache['package_apk_checksums'][package_name] = ret
    return ret

  def _ComputeStaleApks(self, package_name, host_apk_paths):
    def calculate_host_checksums():
      return md5sum.CalculateHostMd5Sums(host_apk_paths)

    def calculate_device_checksums():
      return self._ComputeDeviceChecksumsForApks(package_name)

    host_checksums, device_checksums = reraiser_thread.RunAsync((
        calculate_host_checksums, calculate_device_checksums))
    stale_apks = [k for (k, v) in host_checksums.iteritems()
                  if v not in device_checksums]
    return stale_apks, set(host_checksums.values())

  def _PushFilesImpl(self, host_device_tuples, files):
    if not files:
      return

    size = sum(host_utils.GetRecursiveDiskUsage(h) for h, _ in files)
    file_count = len(files)
    dir_size = sum(host_utils.GetRecursiveDiskUsage(h)
                   for h, _ in host_device_tuples)
    dir_file_count = 0
    for h, _ in host_device_tuples:
      if os.path.isdir(h):
        dir_file_count += sum(len(f) for _r, _d, f in os.walk(h))
      else:
        dir_file_count += 1

    push_duration = self._ApproximateDuration(
        file_count, file_count, size, False)
    dir_push_duration = self._ApproximateDuration(
        len(host_device_tuples), dir_file_count, dir_size, False)
    zip_duration = self._ApproximateDuration(1, 1, size, True)

    if (dir_push_duration < push_duration and dir_push_duration < zip_duration
        # TODO(jbudorick): Resume directory pushing once clients have switched
        # to 1.0.36-compatible syntax.
        and False):
      self._PushChangedFilesIndividually(host_device_tuples)
    elif push_duration < zip_duration:
      self._PushChangedFilesIndividually(files)
    elif self._commands_installed is False:
      # Already tried and failed to install unzip command.
      self._PushChangedFilesIndividually(files)
    elif not self._PushChangedFilesZipped(
        files, [d for _, d in host_device_tuples]):
      self._PushChangedFilesIndividually(files)

  def _MaybeInstallCommands(self):
    if self._commands_installed is None:
      try:
        if not install_commands.Installed(self):
          install_commands.InstallCommands(self)
        self._commands_installed = True
      except device_errors.CommandFailedError as e:
        logger.warning('unzip not available: %s', str(e))
        self._commands_installed = False
    return self._commands_installed

  @staticmethod
  def _ApproximateDuration(adb_calls, file_count, byte_count, is_zipping):
    # We approximate the time to push a set of files to a device as:
    #   t = c1 * a + c2 * f + c3 + b / c4 + b / (c5 * c6), where
    #     t: total time (sec)
    #     c1: adb call time delay (sec)
    #     a: number of times adb is called (unitless)
    #     c2: push time delay (sec)
    #     f: number of files pushed via adb (unitless)
    #     c3: zip time delay (sec)
    #     c4: zip rate (bytes/sec)
    #     b: total number of bytes (bytes)
    #     c5: transfer rate (bytes/sec)
    #     c6: compression ratio (unitless)

    # All of these are approximations.
    ADB_CALL_PENALTY = 0.1  # seconds
    ADB_PUSH_PENALTY = 0.01  # seconds
    ZIP_PENALTY = 2.0  # seconds
    ZIP_RATE = 10000000.0  # bytes / second
    TRANSFER_RATE = 2000000.0  # bytes / second
    COMPRESSION_RATIO = 2.0  # unitless

    adb_call_time = ADB_CALL_PENALTY * adb_calls
    adb_push_setup_time = ADB_PUSH_PENALTY * file_count
    if is_zipping:
      zip_time = ZIP_PENALTY + byte_count / ZIP_RATE
      transfer_time = byte_count / (TRANSFER_RATE * COMPRESSION_RATIO)
    else:
      zip_time = 0
      transfer_time = byte_count / TRANSFER_RATE
    return adb_call_time + adb_push_setup_time + zip_time + transfer_time

  def _PushChangedFilesIndividually(self, files):
    for h, d in files:
      self.adb.Push(h, d)

  def _PushChangedFilesZipped(self, files, dirs):
    with tempfile.NamedTemporaryFile(suffix='.zip') as zip_file:
      zip_proc = multiprocessing.Process(
          target=DeviceUtils._CreateDeviceZip,
          args=(zip_file.name, files))
      zip_proc.start()
      try:
        # While it's zipping, ensure the unzip command exists on the device.
        if not self._MaybeInstallCommands():
          zip_proc.terminate()
          return False

        # Warm up NeedsSU cache while we're still zipping.
        self.NeedsSU()
        with device_temp_file.DeviceTempFile(
            self.adb, suffix='.zip') as device_temp:
          zip_proc.join()
          self.adb.Push(zip_file.name, device_temp.name)
          quoted_dirs = ' '.join(cmd_helper.SingleQuote(d) for d in dirs)
          self.RunShellCommand(
              'unzip %s&&chmod -R 777 %s' % (device_temp.name, quoted_dirs),
              shell=True, as_root=True,
              env={'PATH': '%s:$PATH' % install_commands.BIN_DIR},
              check_return=True)
      finally:
        if zip_proc.is_alive():
          zip_proc.terminate()
    return True

  @staticmethod
  def _CreateDeviceZip(zip_path, host_device_tuples):
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
      for host_path, device_path in host_device_tuples:
        zip_utils.WriteToZipFile(zip_file, host_path, device_path)

  # TODO(nednguyen): remove this and migrate the callsite to PathExists().
  @decorators.WithTimeoutAndRetriesFromInstance()
  def FileExists(self, device_path, timeout=None, retries=None):
    """Checks whether the given file exists on the device.

    Arguments are the same as PathExists.
    """
    return self.PathExists(device_path, timeout=timeout, retries=retries)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def PathExists(self, device_paths, as_root=False, timeout=None, retries=None):
    """Checks whether the given path(s) exists on the device.

    Args:
      device_path: A string containing the absolute path to the file on the
                   device, or an iterable of paths to check.
      as_root: Whether root permissions should be use to check for the existence
               of the given path(s).
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if the all given paths exist on the device, False otherwise.

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    paths = device_paths
    if isinstance(paths, basestring):
      paths = (paths,)
    if not paths:
      return True
    cmd = ['test', '-e', paths[0]]
    for p in paths[1:]:
      cmd.extend(['-a', '-e', p])
    try:
      self.RunShellCommand(cmd, as_root=as_root, check_return=True,
                           timeout=timeout, retries=retries)
      return True
    except device_errors.CommandFailedError:
      return False

  @decorators.WithTimeoutAndRetriesFromInstance()
  def RemovePath(self, device_path, force=False, recursive=False,
                 as_root=False, timeout=None, retries=None):
    """Removes the given path(s) from the device.

    Args:
      device_path: A string containing the absolute path to the file on the
                   device, or an iterable of paths to check.
      force: Whether to remove the path(s) with force (-f).
      recursive: Whether to remove any directories in the path(s) recursively.
      as_root: Whether root permissions should be use to remove the given
               path(s).
      timeout: timeout in seconds
      retries: number of retries
    """
    args = ['rm']
    if force:
      args.append('-f')
    if recursive:
      args.append('-r')
    if isinstance(device_path, basestring):
      args.append(device_path)
    else:
      args.extend(device_path)
    self.RunShellCommand(args, as_root=as_root, check_return=True)


  @decorators.WithTimeoutAndRetriesFromInstance()
  def PullFile(self, device_path, host_path, timeout=None, retries=None):
    """Pull a file from the device.

    Args:
      device_path: A string containing the absolute path of the file to pull
                   from the device.
      host_path: A string containing the absolute path of the destination on
                 the host.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError on timeout.
    """
    # Create the base dir if it doesn't exist already
    dirname = os.path.dirname(host_path)
    if dirname and not os.path.exists(dirname):
      os.makedirs(dirname)
    self.adb.Pull(device_path, host_path)

  def _ReadFileWithPull(self, device_path):
    try:
      d = tempfile.mkdtemp()
      host_temp_path = os.path.join(d, 'tmp_ReadFileWithPull')
      self.adb.Pull(device_path, host_temp_path)
      with open(host_temp_path, 'r') as host_temp:
        return host_temp.read()
    finally:
      if os.path.exists(d):
        shutil.rmtree(d)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def ReadFile(self, device_path, as_root=False, force_pull=False,
               timeout=None, retries=None):
    """Reads the contents of a file from the device.

    Args:
      device_path: A string containing the absolute path of the file to read
                   from the device.
      as_root: A boolean indicating whether the read should be executed with
               root privileges.
      force_pull: A boolean indicating whether to force the operation to be
          performed by pulling a file from the device. The default is, when the
          contents are short, to retrieve the contents using cat instead.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The contents of |device_path| as a string. Contents are intepreted using
      universal newlines, so the caller will see them encoded as '\n'. Also,
      all lines will be terminated.

    Raises:
      AdbCommandFailedError if the file can't be read.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    def get_size(path):
      return self.FileSize(path, as_root=as_root)

    if (not force_pull
        and 0 < get_size(device_path) <= self._MAX_ADB_OUTPUT_LENGTH):
      return _JoinLines(self.RunShellCommand(
          ['cat', device_path], as_root=as_root, check_return=True))
    elif as_root and self.NeedsSU():
      with device_temp_file.DeviceTempFile(self.adb) as device_temp:
        cmd = 'SRC=%s DEST=%s;cp "$SRC" "$DEST" && chmod 666 "$DEST"' % (
            cmd_helper.SingleQuote(device_path),
            cmd_helper.SingleQuote(device_temp.name))
        self.RunShellCommand(cmd, shell=True, as_root=True, check_return=True)
        return self._ReadFileWithPull(device_temp.name)
    else:
      return self._ReadFileWithPull(device_path)

  def _WriteFileWithPush(self, device_path, contents):
    with tempfile.NamedTemporaryFile() as host_temp:
      host_temp.write(contents)
      host_temp.flush()
      self.adb.Push(host_temp.name, device_path)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def WriteFile(self, device_path, contents, as_root=False, force_push=False,
                timeout=None, retries=None):
    """Writes |contents| to a file on the device.

    Args:
      device_path: A string containing the absolute path to the file to write
          on the device.
      contents: A string containing the data to write to the device.
      as_root: A boolean indicating whether the write should be executed with
          root privileges (if available).
      force_push: A boolean indicating whether to force the operation to be
          performed by pushing a file to the device. The default is, when the
          contents are short, to pass the contents using a shell script instead.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if the file could not be written on the device.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    if not force_push and len(contents) < self._MAX_ADB_COMMAND_LENGTH:
      # If the contents are small, for efficieny we write the contents with
      # a shell command rather than pushing a file.
      cmd = 'echo -n %s > %s' % (cmd_helper.SingleQuote(contents),
                                 cmd_helper.SingleQuote(device_path))
      self.RunShellCommand(cmd, shell=True, as_root=as_root, check_return=True)
    elif as_root and self.NeedsSU():
      # Adb does not allow to "push with su", so we first push to a temp file
      # on a safe location, and then copy it to the desired location with su.
      with device_temp_file.DeviceTempFile(self.adb) as device_temp:
        self._WriteFileWithPush(device_temp.name, contents)
        # Here we need 'cp' rather than 'mv' because the temp and
        # destination files might be on different file systems (e.g.
        # on internal storage and an external sd card).
        self.RunShellCommand(['cp', device_temp.name, device_path],
                             as_root=True, check_return=True)
    else:
      # If root is not needed, we can push directly to the desired location.
      self._WriteFileWithPush(device_path, contents)

  def _ParseLongLsOutput(self, device_path, as_root=False, **kwargs):
    """Run and scrape the output of 'ls -a -l' on a device directory."""
    device_path = posixpath.join(device_path, '')  # Force trailing '/'.
    output = self.RunShellCommand(
        ['ls', '-a', '-l', device_path], as_root=as_root,
        check_return=True, env={'TZ': 'utc'}, **kwargs)
    if output and output[0].startswith('total '):
      output.pop(0) # pylint: disable=maybe-no-member

    entries = []
    for line in output:
      m = _LONG_LS_OUTPUT_RE.match(line)
      if m:
        if m.group('filename') not in ['.', '..']:
          entries.append(m.groupdict())
      else:
        logger.info('Skipping: %s', line)

    return entries

  def ListDirectory(self, device_path, as_root=False, **kwargs):
    """List all files on a device directory.

    Mirroring os.listdir (and most client expectations) the resulting list
    does not include the special entries '.' and '..' even if they are present
    in the directory.

    Args:
      device_path: A string containing the path of the directory on the device
                   to list.
      as_root: A boolean indicating whether the to use root privileges to list
               the directory contents.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A list of filenames for all entries contained in the directory.

    Raises:
      AdbCommandFailedError if |device_path| does not specify a valid and
          accessible directory in the device.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    entries = self._ParseLongLsOutput(device_path, as_root=as_root, **kwargs)
    return [d['filename'] for d in entries]

  def StatDirectory(self, device_path, as_root=False, **kwargs):
    """List file and stat info for all entries on a device directory.

    Implementation notes: this is currently implemented by parsing the output
    of 'ls -a -l' on the device. Whether possible and convenient, we attempt to
    make parsing strict and return values mirroring those of the standard |os|
    and |stat| Python modules.

    Mirroring os.listdir (and most client expectations) the resulting list
    does not include the special entries '.' and '..' even if they are present
    in the directory.

    Args:
      device_path: A string containing the path of the directory on the device
                   to list.
      as_root: A boolean indicating whether the to use root privileges to list
               the directory contents.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A list of dictionaries, each containing the following keys:
        filename: A string with the file name.
        st_mode: File permissions, use the stat module to interpret these.
        st_nlink: Number of hard links (may be missing).
        st_owner: A string with the user name of the owner.
        st_group: A string with the group name of the owner.
        st_rdev_pair: Device type as (major, minior) (only if inode device).
        st_size: Size of file, in bytes (may be missing for non-regular files).
        st_mtime: Time of most recent modification, in seconds since epoch
          (although resolution is in minutes).
        symbolic_link_to: If entry is a symbolic link, path where it points to;
          missing otherwise.

    Raises:
      AdbCommandFailedError if |device_path| does not specify a valid and
          accessible directory in the device.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    entries = self._ParseLongLsOutput(device_path, as_root=as_root, **kwargs)
    for d in entries:
      for key, value in d.items():
        if value is None:
          del d[key]  # Remove missing fields.
      d['st_mode'] = _ParseModeString(d['st_mode'])
      d['st_mtime'] = calendar.timegm(
          time.strptime(d['st_mtime'], _LS_DATE_FORMAT))
      for key in ['st_nlink', 'st_size', 'st_rdev_major', 'st_rdev_minor']:
        if key in d:
          d[key] = int(d[key])
      if 'st_rdev_major' in d and 'st_rdev_minor' in d:
        d['st_rdev_pair'] = (d.pop('st_rdev_major'), d.pop('st_rdev_minor'))
    return entries

  def StatPath(self, device_path, as_root=False, **kwargs):
    """Get the stat attributes of a file or directory on the device.

    Args:
      device_path: A string containing the path of a file or directory from
                   which to get attributes.
      as_root: A boolean indicating whether the to use root privileges to
               access the file information.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A dictionary with the stat info collected; see StatDirectory for details.

    Raises:
      CommandFailedError if device_path cannot be found on the device.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    dirname, filename = posixpath.split(posixpath.normpath(device_path))
    for entry in self.StatDirectory(dirname, as_root=as_root, **kwargs):
      if entry['filename'] == filename:
        return entry
    raise device_errors.CommandFailedError(
        'Cannot find file or directory: %r' % device_path, str(self))

  def FileSize(self, device_path, as_root=False, **kwargs):
    """Get the size of a file on the device.

    Note: This is implemented by parsing the output of the 'ls' command on
    the device. On some Android versions, when passing a directory or special
    file, the size is *not* reported and this function will throw an exception.

    Args:
      device_path: A string containing the path of a file on the device.
      as_root: A boolean indicating whether the to use root privileges to
               access the file information.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The size of the file in bytes.

    Raises:
      CommandFailedError if device_path cannot be found on the device, or
        its size cannot be determited for some reason.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    entry = self.StatPath(device_path, as_root=as_root, **kwargs)
    try:
      return entry['st_size']
    except KeyError:
      raise device_errors.CommandFailedError(
          'Could not determine the size of: %s' % device_path, str(self))

  @decorators.WithTimeoutAndRetriesFromInstance()
  def SetJavaAsserts(self, enabled, timeout=None, retries=None):
    """Enables or disables Java asserts.

    Args:
      enabled: A boolean indicating whether Java asserts should be enabled
               or disabled.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True if the device-side property changed and a restart is required as a
      result, False otherwise.

    Raises:
      CommandTimeoutError on timeout.
    """
    def find_property(lines, property_name):
      for index, line in enumerate(lines):
        if line.strip() == '':
          continue
        key_value = tuple(s.strip() for s in line.split('=', 1))
        if len(key_value) != 2:
          continue
        key, value = key_value
        if key == property_name:
          return index, value
      return None, ''

    new_value = 'all' if enabled else ''

    # First ensure the desired property is persisted.
    try:
      properties = self.ReadFile(self.LOCAL_PROPERTIES_PATH).splitlines()
    except device_errors.CommandFailedError:
      properties = []
    index, value = find_property(properties, self.JAVA_ASSERT_PROPERTY)
    if new_value != value:
      if new_value:
        new_line = '%s=%s' % (self.JAVA_ASSERT_PROPERTY, new_value)
        if index is None:
          properties.append(new_line)
        else:
          properties[index] = new_line
      else:
        assert index is not None  # since new_value == '' and new_value != value
        properties.pop(index)
      self.WriteFile(self.LOCAL_PROPERTIES_PATH, _JoinLines(properties))

    # Next, check the current runtime value is what we need, and
    # if not, set it and report that a reboot is required.
    value = self.GetProp(self.JAVA_ASSERT_PROPERTY)
    if new_value != value:
      self.SetProp(self.JAVA_ASSERT_PROPERTY, new_value)
      return True
    else:
      return False

  def GetLanguage(self, cache=False):
    """Returns the language setting on the device.
    Args:
      cache: Whether to use cached properties when available.
    """
    return self.GetProp('persist.sys.language', cache=cache)

  def GetCountry(self, cache=False):
    """Returns the country setting on the device.

    Args:
      cache: Whether to use cached properties when available.
    """
    return self.GetProp('persist.sys.country', cache=cache)

  @property
  def screen_density(self):
    """Returns the screen density of the device."""
    DPI_TO_DENSITY = {
      120: 'ldpi',
      160: 'mdpi',
      240: 'hdpi',
      320: 'xhdpi',
      480: 'xxhdpi',
      640: 'xxxhdpi',
    }
    return DPI_TO_DENSITY.get(self.pixel_density, 'tvdpi')

  @property
  def pixel_density(self):
    return int(self.GetProp('ro.sf.lcd_density', cache=True))

  @property
  def build_description(self):
    """Returns the build description of the system.

    For example:
      nakasi-user 4.4.4 KTU84P 1227136 release-keys
    """
    return self.GetProp('ro.build.description', cache=True)

  @property
  def build_fingerprint(self):
    """Returns the build fingerprint of the system.

    For example:
      google/nakasi/grouper:4.4.4/KTU84P/1227136:user/release-keys
    """
    return self.GetProp('ro.build.fingerprint', cache=True)

  @property
  def build_id(self):
    """Returns the build ID of the system (e.g. 'KTU84P')."""
    return self.GetProp('ro.build.id', cache=True)

  @property
  def build_product(self):
    """Returns the build product of the system (e.g. 'grouper')."""
    return self.GetProp('ro.build.product', cache=True)

  @property
  def build_type(self):
    """Returns the build type of the system (e.g. 'user')."""
    return self.GetProp('ro.build.type', cache=True)

  @property
  def build_version_sdk(self):
    """Returns the build version sdk of the system as a number (e.g. 19).

    For version code numbers see:
    http://developer.android.com/reference/android/os/Build.VERSION_CODES.html

    For named constants see devil.android.sdk.version_codes

    Raises:
      CommandFailedError if the build version sdk is not a number.
    """
    value = self.GetProp('ro.build.version.sdk', cache=True)
    try:
      return int(value)
    except ValueError:
      raise device_errors.CommandFailedError(
          'Invalid build version sdk: %r' % value)

  @property
  def product_cpu_abi(self):
    """Returns the product cpu abi of the device (e.g. 'armeabi-v7a')."""
    return self.GetProp('ro.product.cpu.abi', cache=True)

  @property
  def product_model(self):
    """Returns the name of the product model (e.g. 'Nexus 7')."""
    return self.GetProp('ro.product.model', cache=True)

  @property
  def product_name(self):
    """Returns the product name of the device (e.g. 'nakasi')."""
    return self.GetProp('ro.product.name', cache=True)

  @property
  def product_board(self):
    """Returns the product board name of the device (e.g. 'shamu')."""
    return self.GetProp('ro.product.board', cache=True)

  def _EnsureCacheInitialized(self):
    """Populates cache token, runs getprop and fetches $EXTERNAL_STORAGE."""
    if self._cache['token']:
      return
    with self._cache_lock:
      if self._cache['token']:
        return
      # Change the token every time to ensure that it will match only the
      # previously dumped cache.
      token = str(uuid.uuid1())
      cmd = (
          'c=/data/local/tmp/cache_token;'
          'echo $EXTERNAL_STORAGE;'
          'cat $c 2>/dev/null||echo;'
          'echo "%s">$c &&' % token +
          'getprop'
      )
      output = self.RunShellCommand(
          cmd, shell=True, check_return=True, large_output=True)
      # Error-checking for this existing is done in GetExternalStoragePath().
      self._cache['external_storage'] = output[0]
      self._cache['prev_token'] = output[1]
      output = output[2:]

      prop_cache = self._cache['getprop']
      prop_cache.clear()
      for key, value in _GETPROP_RE.findall(''.join(output)):
        prop_cache[key] = value
      self._cache['token'] = token

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetProp(self, property_name, cache=False, timeout=None, retries=None):
    """Gets a property from the device.

    Args:
      property_name: A string containing the name of the property to get from
                     the device.
      cache: Whether to use cached properties when available.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The value of the device's |property_name| property.

    Raises:
      CommandTimeoutError on timeout.
    """
    assert isinstance(property_name, basestring), (
        "property_name is not a string: %r" % property_name)

    if cache:
      # It takes ~120ms to query a single property, and ~130ms to query all
      # properties. So, when caching we always query all properties.
      self._EnsureCacheInitialized()
    else:
      # timeout and retries are handled down at run shell, because we don't
      # want to apply them in the other branch when reading from the cache
      value = self.RunShellCommand(
          ['getprop', property_name], single_line=True, check_return=True,
          timeout=timeout, retries=retries)
      self._cache['getprop'][property_name] = value
    # Non-existent properties are treated as empty strings by getprop.
    return self._cache['getprop'].get(property_name, '')

  @decorators.WithTimeoutAndRetriesFromInstance()
  def SetProp(self, property_name, value, check=False, timeout=None,
              retries=None):
    """Sets a property on the device.

    Args:
      property_name: A string containing the name of the property to set on
                     the device.
      value: A string containing the value to set to the property on the
             device.
      check: A boolean indicating whether to check that the property was
             successfully set on the device.
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError if check is true and the property was not correctly
        set on the device (e.g. because it is not rooted).
      CommandTimeoutError on timeout.
    """
    assert isinstance(property_name, basestring), (
        "property_name is not a string: %r" % property_name)
    assert isinstance(value, basestring), "value is not a string: %r" % value

    self.RunShellCommand(['setprop', property_name, value], check_return=True)
    prop_cache = self._cache['getprop']
    if property_name in prop_cache:
      del prop_cache[property_name]
    # TODO(perezju) remove the option and make the check mandatory, but using a
    # single shell script to both set- and getprop.
    if check and value != self.GetProp(property_name, cache=False):
      raise device_errors.CommandFailedError(
          'Unable to set property %r on the device to %r'
          % (property_name, value), str(self))

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetABI(self, timeout=None, retries=None):
    """Gets the device main ABI.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The device's main ABI name.

    Raises:
      CommandTimeoutError on timeout.
    """
    return self.GetProp('ro.product.cpu.abi', cache=True)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetPids(self, process_name=None, timeout=None, retries=None):
    """Returns the PIDs of processes containing the given name as substring.

    Note that the |process_name| is often the package name.

    Args:
      process_name: A string containing the process name to get the PIDs for.
                    If missing returns PIDs for all processes.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A dict mapping process name to a list of PIDs for each process that
      contained the provided |process_name|.

    Raises:
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    procs_pids = collections.defaultdict(list)
    try:
      ps_cmd = 'ps'
      # ps behavior was changed in Android above N, http://crbug.com/686716
      if (self.build_version_sdk >= version_codes.NOUGAT_MR1
          and self.build_id[0] > 'N'):
        ps_cmd = 'ps -e'
      if process_name:
        ps_output = self._RunPipedShellCommand(
            '%s | grep -F %s' % (ps_cmd, cmd_helper.SingleQuote(process_name)))
      else:
        ps_output = self.RunShellCommand(
            ps_cmd.split(), check_return=True, large_output=True)
    except device_errors.AdbShellCommandFailedError as e:
      if e.status and isinstance(e.status, list) and not e.status[0]:
        # If ps succeeded but grep failed, there were no processes with the
        # given name.
        return procs_pids
      else:
        raise

    process_name = process_name or ''
    for line in ps_output:
      try:
        ps_data = line.split()
        pid, process = ps_data[1], ps_data[-1]
        if process_name in process and pid != 'PID':
          procs_pids[process].append(pid)
      except IndexError:
        pass
    return procs_pids

  def GetApplicationPids(self, process_name, at_most_one=False, **kwargs):
    """Returns the PID or PIDs of a given process name.

    Note that the |process_name|, often the package name, must match exactly.

    Args:
      process_name: A string containing the process name to get the PIDs for.
      at_most_one: A boolean indicating that at most one PID is expected to
                   be found.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A list of the PIDs for the named process. If at_most_one=True returns
      the single PID found or None otherwise.

    Raises:
      CommandFailedError if at_most_one=True and more than one PID is found
          for the named process.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    pids = self.GetPids(process_name, **kwargs).get(process_name, [])
    if at_most_one:
      if len(pids) > 1:
        raise device_errors.CommandFailedError(
            'Expected a single process but found PIDs: %s.' % ', '.join(pids),
            device_serial=str(self))
      return pids[0] if pids else None
    else:
      return pids

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetEnforce(self, timeout=None, retries=None):
    """Get the current mode of SELinux.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      True (enforcing), False (permissive), or None (disabled).

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    output = self.RunShellCommand(
        ['getenforce'], check_return=True, single_line=True).lower()
    if output not in _SELINUX_MODE:
      raise device_errors.CommandFailedError(
          'Unexpected getenforce output: %s' % output)
    return _SELINUX_MODE[output]

  @decorators.WithTimeoutAndRetriesFromInstance()
  def SetEnforce(self, enabled, timeout=None, retries=None):
    """Modify the mode SELinux is running in.

    Args:
      enabled: a boolean indicating whether to put SELinux in encorcing mode
               (if True), or permissive mode (otherwise).
      timeout: timeout in seconds
      retries: number of retries

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    self.RunShellCommand(
        ['setenforce', '1' if int(enabled) else '0'], as_root=True,
        check_return=True)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def TakeScreenshot(self, host_path=None, timeout=None, retries=None):
    """Takes a screenshot of the device.

    Args:
      host_path: A string containing the path on the host to save the
                 screenshot to. If None, a file name in the current
                 directory will be generated.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      The name of the file on the host to which the screenshot was saved.

    Raises:
      CommandFailedError on failure.
      CommandTimeoutError on timeout.
      DeviceUnreachableError on missing device.
    """
    if not host_path:
      host_path = os.path.abspath('screenshot-%s-%s.png' % (
          self.serial, _GetTimeStamp()))
    with device_temp_file.DeviceTempFile(self.adb, suffix='.png') as device_tmp:
      self.RunShellCommand(['/system/bin/screencap', '-p', device_tmp.name],
                           check_return=True)
      self.PullFile(device_tmp.name, host_path)
    return host_path

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GetMemoryUsageForPid(self, pid, timeout=None, retries=None):
    """Gets the memory usage for the given PID.

    Args:
      pid: PID of the process.
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A dict containing memory usage statistics for the PID. May include:
        Size, Rss, Pss, Shared_Clean, Shared_Dirty, Private_Clean,
        Private_Dirty, VmHWM

    Raises:
      CommandTimeoutError on timeout.
    """
    result = collections.defaultdict(int)

    try:
      result.update(self._GetMemoryUsageForPidFromSmaps(pid))
    except device_errors.CommandFailedError:
      logger.exception('Error getting memory usage from smaps')

    try:
      result.update(self._GetMemoryUsageForPidFromStatus(pid))
    except device_errors.CommandFailedError:
      logger.exception('Error getting memory usage from status')

    return result

  @decorators.WithTimeoutAndRetriesFromInstance()
  def DismissCrashDialogIfNeeded(self, timeout=None, retries=None):
    """Dismiss the error/ANR dialog if present.

    Returns: Name of the crashed package if a dialog is focused,
             None otherwise.
    """
    def _FindFocusedWindow():
      match = None
      # TODO(jbudorick): Try to grep the output on the device instead of using
      # large_output if/when DeviceUtils exposes a public interface for piped
      # shell command handling.
      for line in self.RunShellCommand(['dumpsys', 'window', 'windows'],
                                       check_return=True, large_output=True):
        match = re.match(_CURRENT_FOCUS_CRASH_RE, line)
        if match:
          break
      return match

    match = _FindFocusedWindow()
    if not match:
      return None
    package = match.group(2)
    logger.warning('Trying to dismiss %s dialog for %s', *match.groups())
    self.SendKeyEvent(keyevent.KEYCODE_DPAD_RIGHT)
    self.SendKeyEvent(keyevent.KEYCODE_DPAD_RIGHT)
    self.SendKeyEvent(keyevent.KEYCODE_ENTER)
    match = _FindFocusedWindow()
    if match:
      logger.error('Still showing a %s dialog for %s', *match.groups())
    return package

  def _GetMemoryUsageForPidFromSmaps(self, pid):
    SMAPS_COLUMNS = (
        'Size', 'Rss', 'Pss', 'Shared_Clean', 'Shared_Dirty', 'Private_Clean',
        'Private_Dirty')

    showmap_out = self._RunPipedShellCommand(
        'showmap %d | grep TOTAL' % int(pid), as_root=True)

    split_totals = showmap_out[-1].split()
    if (not split_totals
        or len(split_totals) != 9
        or split_totals[-1] != 'TOTAL'):
      raise device_errors.CommandFailedError(
          'Invalid output from showmap: %s' % '\n'.join(showmap_out))

    return dict(itertools.izip(SMAPS_COLUMNS, (int(n) for n in split_totals)))

  def _GetMemoryUsageForPidFromStatus(self, pid):
    for line in self.ReadFile(
        '/proc/%s/status' % str(pid), as_root=True).splitlines():
      if line.startswith('VmHWM:'):
        return {'VmHWM': int(line.split()[1])}
    raise device_errors.CommandFailedError(
        'Could not find memory peak value for pid %s', str(pid))

  def GetLogcatMonitor(self, *args, **kwargs):
    """Returns a new LogcatMonitor associated with this device.

    Parameters passed to this function are passed directly to
    |logcat_monitor.LogcatMonitor| and are documented there.
    """
    return logcat_monitor.LogcatMonitor(self.adb, *args, **kwargs)

  def GetClientCache(self, client_name):
    """Returns client cache."""
    if client_name not in self._client_caches:
      self._client_caches[client_name] = {}
    return self._client_caches[client_name]

  def _ClearCache(self):
    """Clears all caches."""
    for client in self._client_caches:
      self._client_caches[client].clear()
    self._cache = {
        # Map of packageId -> list of on-device .apk paths
        'package_apk_paths': {},
        # Set of packageId that were loaded from LoadCacheData and not yet
        # verified.
        'package_apk_paths_to_verify': set(),
        # Map of packageId -> set of on-device .apk checksums
        'package_apk_checksums': {},
        # Map of property_name -> value
        'getprop': {},
        # Map of device_path -> [ignore_other_files, map of path->checksum]
        'device_path_checksums': {},
        # Location of sdcard ($EXTERNAL_STORAGE).
        'external_storage': None,
        # Token used to detect when LoadCacheData is stale.
        'token': None,
        'prev_token': None,
    }

  @decorators.WithTimeoutAndRetriesFromInstance()
  def LoadCacheData(self, data, timeout=None, retries=None):
    """Initializes the cache from data created using DumpCacheData.

    The cache is used only if its token matches the one found on the device.
    This prevents a stale cache from being used (which can happen when sharing
    devices).

    Args:
      data: A previously serialized cache (string).
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      Whether the cache was loaded.
    """
    obj = json.loads(data)
    self._EnsureCacheInitialized()
    given_token = obj.get('token')
    if not given_token or self._cache['prev_token'] != given_token:
      logger.warning('Stale cache detected. Not using it.')
      return False

    self._cache['package_apk_paths'] = obj.get('package_apk_paths', {})
    # When using a cache across script invokations, verify that apps have
    # not been uninstalled.
    self._cache['package_apk_paths_to_verify'] = set(
        self._cache['package_apk_paths'].iterkeys())

    package_apk_checksums = obj.get('package_apk_checksums', {})
    for k, v in package_apk_checksums.iteritems():
      package_apk_checksums[k] = set(v)
    self._cache['package_apk_checksums'] = package_apk_checksums
    device_path_checksums = obj.get('device_path_checksums', {})
    self._cache['device_path_checksums'] = device_path_checksums
    return True

  @decorators.WithTimeoutAndRetriesFromInstance()
  def DumpCacheData(self, timeout=None, retries=None):
    """Dumps the current cache state to a string.

    Args:
      timeout: timeout in seconds
      retries: number of retries

    Returns:
      A serialized cache as a string.
    """
    self._EnsureCacheInitialized()
    obj = {}
    obj['token'] = self._cache['token']
    obj['package_apk_paths'] = self._cache['package_apk_paths']
    obj['package_apk_checksums'] = self._cache['package_apk_checksums']
    # JSON can't handle sets.
    for k, v in obj['package_apk_checksums'].iteritems():
      obj['package_apk_checksums'][k] = list(v)
    obj['device_path_checksums'] = self._cache['device_path_checksums']
    return json.dumps(obj, separators=(',', ':'))

  @classmethod
  def parallel(cls, devices, async=False):
    """Creates a Parallelizer to operate over the provided list of devices.

    Args:
      devices: A list of either DeviceUtils instances or objects from
               from which DeviceUtils instances can be constructed. If None,
               all attached devices will be used.
      async: If true, returns a Parallelizer that runs operations
             asynchronously.

    Returns:
      A Parallelizer operating over |devices|.
    """
    devices = [d if isinstance(d, cls) else cls(d) for d in devices]
    if async:
      return parallelizer.Parallelizer(devices)
    else:
      return parallelizer.SyncParallelizer(devices)

  @classmethod
  def HealthyDevices(cls, blacklist=None, device_arg='default', **kwargs):
    """Returns a list of DeviceUtils instances.

    Returns a list of DeviceUtils instances that are attached, not blacklisted,
    and optionally filtered by --device flags or ANDROID_SERIAL environment
    variable.

    Args:
      blacklist: A DeviceBlacklist instance (optional). Device serials in this
          blacklist will never be returned, but a warning will be logged if they
          otherwise would have been.
      device_arg: The value of the --device flag. This can be:
          'default' -> Same as [], but returns an empty list rather than raise a
              NoDevicesError.
          [] -> Returns all devices, unless $ANDROID_SERIAL is set.
          None -> Use $ANDROID_SERIAL if set, otherwise looks for a single
              attached device. Raises an exception if multiple devices are
              attached.
          'serial' -> Returns an instance for the given serial, if not
              blacklisted.
          ['A', 'B', ...] -> Returns instances for the subset that is not
              blacklisted.
      A device serial, or a list of device serials (optional).

    Returns:
      A list of DeviceUtils instances.

    Raises:
      NoDevicesError: Raised when no non-blacklisted devices exist and
          device_arg is passed.
      MultipleDevicesError: Raise when multiple devices exist, but |device_arg|
          is None.
    """
    allow_no_devices = False
    if device_arg == 'default':
      allow_no_devices = True
      device_arg = ()

    select_multiple = True
    if not (isinstance(device_arg, tuple) or isinstance(device_arg, list)):
      select_multiple = False
      if device_arg:
        device_arg = (device_arg,)

    blacklisted_devices = blacklist.Read() if blacklist else []

    # adb looks for ANDROID_SERIAL, so support it as well.
    android_serial = os.environ.get('ANDROID_SERIAL')
    if not device_arg and android_serial:
      device_arg = (android_serial,)

    def blacklisted(serial):
      if serial in blacklisted_devices:
        logger.warning('Device %s is blacklisted.', serial)
        return True
      return False

    if device_arg:
      devices = [cls(x, **kwargs) for x in device_arg if not blacklisted(x)]
    else:
      devices = []
      for adb in adb_wrapper.AdbWrapper.Devices():
        if not blacklisted(adb.GetDeviceSerial()):
          devices.append(cls(_CreateAdbWrapper(adb), **kwargs))

    if len(devices) == 0 and not allow_no_devices:
      raise device_errors.NoDevicesError()
    if len(devices) > 1 and not select_multiple:
      raise device_errors.MultipleDevicesError(devices)
    return sorted(devices)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def RestartAdbd(self, timeout=None, retries=None):
    logger.info('Restarting adbd on device.')
    with device_temp_file.DeviceTempFile(self.adb, suffix='.sh') as script:
      self.WriteFile(script.name, _RESTART_ADBD_SCRIPT)
      self.RunShellCommand(
          ['source', script.name], check_return=True, as_root=True)
      self.adb.WaitForDevice()

  @decorators.WithTimeoutAndRetriesFromInstance()
  def GrantPermissions(self, package, permissions, timeout=None, retries=None):
    # Permissions only need to be set on M and above because of the changes to
    # the permission model.
    if not permissions or self.build_version_sdk < version_codes.MARSHMALLOW:
      return
    logger.info('Setting permissions for %s.', package)
    permissions = [p for p in permissions if p not in _PERMISSIONS_BLACKLIST]
    if ('android.permission.WRITE_EXTERNAL_STORAGE' in permissions
        and 'android.permission.READ_EXTERNAL_STORAGE' not in permissions):
      permissions.append('android.permission.READ_EXTERNAL_STORAGE')
    cmd = '&&'.join('pm grant %s %s' % (package, p) for p in permissions)
    if cmd:
      output = self.RunShellCommand(cmd, shell=True, check_return=True)
      if output:
        logger.warning('Possible problem when granting permissions. Blacklist '
                       'may need to be updated.')
        for line in output:
          logger.warning('  %s', line)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def IsScreenOn(self, timeout=None, retries=None):
    """Determines if screen is on.

    Dumpsys input_method exposes screen on/off state. Below is an explination of
    the states.

    Pre-L:
      On: mScreenOn=true
      Off: mScreenOn=false
    L+:
      On: mInteractive=true
      Off: mInteractive=false

    Returns:
      True if screen is on, false if it is off.

    Raises:
      device_errors.CommandFailedError: If screen state cannot be found.
    """
    if self.build_version_sdk < version_codes.LOLLIPOP:
      input_check = 'mScreenOn'
      check_value = 'mScreenOn=true'
    else:
      input_check = 'mInteractive'
      check_value = 'mInteractive=true'
    dumpsys_out = self._RunPipedShellCommand(
        'dumpsys input_method | grep %s' % input_check)
    if not dumpsys_out:
      raise device_errors.CommandFailedError(
          'Unable to detect screen state', str(self))
    return check_value in dumpsys_out[0]

  @decorators.WithTimeoutAndRetriesFromInstance()
  def SetScreen(self, on, timeout=None, retries=None):
    """Turns screen on and off.

    Args:
      on: bool to decide state to switch to. True = on False = off.
    """
    def screen_test():
      return self.IsScreenOn() == on

    if screen_test():
      logger.info('Screen already in expected state.')
      return
    self.SendKeyEvent(keyevent.KEYCODE_POWER)
    timeout_retry.WaitFor(screen_test, wait_period=1)
