#!/usr/bin/env python
#
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provisions Android devices with settings required for bots.

Usage:
  ./provision_devices.py [-d <device serial number>]
"""

import argparse
import datetime
import json
import logging
import os
import posixpath
import re
import sys
import time

# Import _strptime before threaded code. datetime.datetime.strptime is
# threadsafe except for the initial import of the _strptime module.
# See crbug.com/584730 and https://bugs.python.org/issue7980.
import _strptime  # pylint: disable=unused-import

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   '..', '..', '..')))

from devil import devil_env
from devil.android import battery_utils
from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_temp_file
from devil.android import device_utils
from devil.android import settings
from devil.android.constants import chrome
from devil.android.sdk import adb_wrapper
from devil.android.sdk import intent
from devil.android.sdk import keyevent
from devil.android.sdk import version_codes
from devil.android.tools import script_common
from devil.constants import exit_codes
from devil.utils import run_tests_helper
from devil.utils import timeout_retry

logger = logging.getLogger(__name__)

_SYSTEM_APP_DIRECTORIES = ['/system/app/', '/system/priv-app/']
_SYSTEM_WEBVIEW_NAMES = ['webview', 'WebViewGoogle']
_CHROME_PACKAGE_REGEX = re.compile('.*chrom.*')
_TOMBSTONE_REGEX = re.compile('tombstone.*')


class _DEFAULT_TIMEOUTS(object):
  # L can take a while to reboot after a wipe.
  LOLLIPOP = 600
  PRE_LOLLIPOP = 180

  HELP_TEXT = '{}s on L, {}s on pre-L'.format(LOLLIPOP, PRE_LOLLIPOP)


class ProvisionStep(object):

  def __init__(self, cmd, reboot=False):
    self.cmd = cmd
    self.reboot = reboot


def ProvisionDevices(
    devices,
    blacklist_file,
    adb_key_files=None,
    disable_location=False,
    disable_mock_location=False,
    disable_network=False,
    disable_system_chrome=False,
    emulators=False,
    enable_java_debug=False,
    max_battery_temp=None,
    min_battery_level=None,
    output_device_blacklist=None,
    reboot_timeout=None,
    remove_system_webview=False,
    system_app_remove_list=None,
    wipe=True):
  blacklist = (device_blacklist.Blacklist(blacklist_file)
               if blacklist_file
               else None)
  system_app_remove_list = system_app_remove_list or []
  try:
    devices = script_common.GetDevices(devices, blacklist)
  except device_errors.NoDevicesError:
    logging.error('No available devices to provision.')
    if blacklist:
      logging.error('Local device blacklist: %s', blacklist.Read())
    raise
  devices = [d for d in devices
             if not emulators or d.adb.is_emulator]
  parallel_devices = device_utils.DeviceUtils.parallel(devices)

  steps = []
  if wipe:
    steps += [ProvisionStep(lambda d: Wipe(d, adb_key_files), reboot=True)]
  steps += [ProvisionStep(
      lambda d: SetProperties(d, enable_java_debug, disable_location,
                              disable_mock_location),
      reboot=not emulators)]

  if disable_network:
    steps.append(ProvisionStep(DisableNetwork))

  if disable_system_chrome:
    steps.append(ProvisionStep(DisableSystemChrome))

  if max_battery_temp:
    steps.append(ProvisionStep(
        lambda d: WaitForTemperature(d, max_battery_temp)))

  if min_battery_level:
    steps.append(ProvisionStep(
        lambda d: WaitForCharge(d, min_battery_level)))

  if remove_system_webview:
    system_app_remove_list.extend(_SYSTEM_WEBVIEW_NAMES)

  if system_app_remove_list:
    steps.append(ProvisionStep(
        lambda d: RemoveSystemApps(d, system_app_remove_list)))

  steps.append(ProvisionStep(SetDate))
  steps.append(ProvisionStep(CheckExternalStorage))

  parallel_devices.pMap(ProvisionDevice, steps, blacklist, reboot_timeout)

  blacklisted_devices = blacklist.Read() if blacklist else []
  if output_device_blacklist:
    with open(output_device_blacklist, 'w') as f:
      json.dump(blacklisted_devices, f)
  if all(d in blacklisted_devices for d in devices):
    raise device_errors.NoDevicesError
  return 0


def ProvisionDevice(device, steps, blacklist, reboot_timeout=None):
  try:
    if not reboot_timeout:
      if device.build_version_sdk >= version_codes.LOLLIPOP:
        reboot_timeout = _DEFAULT_TIMEOUTS.LOLLIPOP
      else:
        reboot_timeout = _DEFAULT_TIMEOUTS.PRE_LOLLIPOP

    for step in steps:
      try:
        device.WaitUntilFullyBooted(timeout=reboot_timeout, retries=0)
      except device_errors.CommandTimeoutError:
        logger.error('Device did not finish booting. Will try to reboot.')
        device.Reboot(timeout=reboot_timeout)
      step.cmd(device)
      if step.reboot:
        device.Reboot(False, retries=0)
        device.adb.WaitForDevice()

  except device_errors.CommandTimeoutError:
    logger.exception('Timed out waiting for device %s. Adding to blacklist.',
                     str(device))
    if blacklist:
      blacklist.Extend([str(device)], reason='provision_timeout')

  except device_errors.CommandFailedError:
    logger.exception('Failed to provision device %s. Adding to blacklist.',
                     str(device))
    if blacklist:
      blacklist.Extend([str(device)], reason='provision_failure')


def Wipe(device, adb_key_files=None):
  if (device.IsUserBuild() or
      device.build_version_sdk >= version_codes.MARSHMALLOW):
    WipeChromeData(device)

    package = "com.google.android.gms"
    version_name = device.GetApplicationVersion(package)
    logger.info("Version name for %s is %s", package, version_name)
  else:
    WipeDevice(device, adb_key_files)


def WipeChromeData(device):
  """Wipes chrome specific data from device

  (1) uninstall any app whose name matches *chrom*, except
      com.android.chrome, which is the chrome stable package. Doing so also
      removes the corresponding dirs under /data/data/ and /data/app/
  (2) remove any dir under /data/app-lib/ whose name matches *chrom*
  (3) remove any files under /data/tombstones/ whose name matches "tombstone*"
  (4) remove /data/local.prop if there is any
  (5) remove /data/local/chrome-command-line if there is any
  (6) remove anything under /data/local/.config/ if the dir exists
      (this is telemetry related)
  (7) remove anything under /data/local/tmp/

  Arguments:
    device: the device to wipe
  """
  try:
    if device.IsUserBuild():
      _UninstallIfMatch(device, _CHROME_PACKAGE_REGEX,
                        chrome.PACKAGE_INFO['chrome_stable'].package)
      device.RunShellCommand('rm -rf %s/*' % device.GetExternalStoragePath(),
                             shell=True, check_return=True)
      device.RunShellCommand('rm -rf /data/local/tmp/*',
                             shell=True, check_return=True)
    else:
      device.EnableRoot()
      _UninstallIfMatch(device, _CHROME_PACKAGE_REGEX,
                        chrome.PACKAGE_INFO['chrome_stable'].package)
      _WipeUnderDirIfMatch(device, '/data/app-lib/', _CHROME_PACKAGE_REGEX)
      _WipeUnderDirIfMatch(device, '/data/tombstones/', _TOMBSTONE_REGEX)

      _WipeFileOrDir(device, '/data/local.prop')
      _WipeFileOrDir(device, '/data/local/chrome-command-line')
      _WipeFileOrDir(device, '/data/local/.config/')
      _WipeFileOrDir(device, '/data/local/tmp/')
      device.RunShellCommand('rm -rf %s/*' % device.GetExternalStoragePath(),
                             shell=True, check_return=True)
  except device_errors.CommandFailedError:
    logger.exception('Possible failure while wiping the device. '
                     'Attempting to continue.')


def _UninstallIfMatch(device, pattern, app_to_keep):
  installed_packages = device.RunShellCommand(
      ['pm', 'list', 'packages'], check_return=True)
  installed_system_packages = [
      pkg.split(':')[1] for pkg in device.RunShellCommand(
          ['pm', 'list', 'packages', '-s'], check_return=True)]
  for package_output in installed_packages:
    package = package_output.split(":")[1]
    if pattern.match(package) and not package == app_to_keep:
      if not device.IsUserBuild() or package not in installed_system_packages:
        device.Uninstall(package)


def _WipeUnderDirIfMatch(device, path, pattern):
  for filename in device.ListDirectory(path):
    if pattern.match(filename):
      _WipeFileOrDir(device, posixpath.join(path, filename))


def _WipeFileOrDir(device, path):
  if device.PathExists(path):
    device.RunShellCommand(['rm', '-rf', path], check_return=True)


def WipeDevice(device, adb_key_files):
  """Wipes data from device, keeping only the adb_keys for authorization.

  After wiping data on a device that has been authorized, adb can still
  communicate with the device, but after reboot the device will need to be
  re-authorized because the adb keys file is stored in /data/misc/adb/.
  Thus, adb_keys file is rewritten so the device does not need to be
  re-authorized.

  Arguments:
    device: the device to wipe
  """
  try:
    device.EnableRoot()
    device_authorized = device.FileExists(adb_wrapper.ADB_KEYS_FILE)
    if device_authorized:
      adb_keys = device.ReadFile(adb_wrapper.ADB_KEYS_FILE,
                                 as_root=True).splitlines()
    device.RunShellCommand(['wipe', 'data'],
                           as_root=True, check_return=True)
    device.adb.WaitForDevice()

    if device_authorized:
      adb_keys_set = set(adb_keys)
      for adb_key_file in adb_key_files or []:
        try:
          with open(adb_key_file, 'r') as f:
            adb_public_keys = f.readlines()
          adb_keys_set.update(adb_public_keys)
        except IOError:
          logger.warning('Unable to find adb keys file %s.', adb_key_file)
      _WriteAdbKeysFile(device, '\n'.join(adb_keys_set))
  except device_errors.CommandFailedError:
    logger.exception('Possible failure while wiping the device. '
                     'Attempting to continue.')


def _WriteAdbKeysFile(device, adb_keys_string):
  dir_path = posixpath.dirname(adb_wrapper.ADB_KEYS_FILE)
  device.RunShellCommand(['mkdir', '-p', dir_path],
                         as_root=True, check_return=True)
  device.RunShellCommand(['restorecon', dir_path],
                         as_root=True, check_return=True)
  device.WriteFile(adb_wrapper.ADB_KEYS_FILE, adb_keys_string, as_root=True)
  device.RunShellCommand(['restorecon', adb_wrapper.ADB_KEYS_FILE],
                         as_root=True, check_return=True)


def SetProperties(device, enable_java_debug, disable_location,
                  disable_mock_location):
  try:
    device.EnableRoot()
  except device_errors.CommandFailedError as e:
    logger.warning(str(e))

  if not device.IsUserBuild():
    _ConfigureLocalProperties(device, enable_java_debug)
  else:
    logger.warning('Cannot configure properties in user builds.')
  settings.ConfigureContentSettings(
      device, settings.DETERMINISTIC_DEVICE_SETTINGS)
  if disable_location:
    settings.ConfigureContentSettings(
        device, settings.DISABLE_LOCATION_SETTINGS)
  else:
    settings.ConfigureContentSettings(
        device, settings.ENABLE_LOCATION_SETTINGS)

  if disable_mock_location:
    settings.ConfigureContentSettings(
        device, settings.DISABLE_MOCK_LOCATION_SETTINGS)
  else:
    settings.ConfigureContentSettings(
        device, settings.ENABLE_MOCK_LOCATION_SETTINGS)

  settings.SetLockScreenSettings(device)

  # Some device types can momentarily disappear after setting properties.
  device.adb.WaitForDevice()


def DisableNetwork(device):
  settings.ConfigureContentSettings(
      device, settings.NETWORK_DISABLED_SETTINGS)
  if device.build_version_sdk >= version_codes.MARSHMALLOW:
    # Ensure that NFC is also switched off.
    device.RunShellCommand(['svc', 'nfc', 'disable'],
                           as_root=True, check_return=True)


def DisableSystemChrome(device):
  # The system chrome version on the device interferes with some tests.
  device.RunShellCommand(['pm', 'disable', 'com.android.chrome'],
                         check_return=True)


def _RemoveSystemApp(device, system_app):
  found_paths = []
  for directory in _SYSTEM_APP_DIRECTORIES:
    path = os.path.join(directory, system_app)
    if device.PathExists(path):
      found_paths.append(path)
  if not found_paths:
    logger.warning('Could not find install location for system app %s',
                   system_app)
  device.RemovePath(found_paths, force=True, recursive=True)

def RemoveSystemApps(device, system_app_remove_list):
  """Attempts to remove the provided system apps from the given device.

  Arguments:
    device: The device to remove the system apps from.
    system_app_remove_list: A list of app names to remove, e.g.
        ['WebViewGoogle', 'GoogleVrCore']
  """
  device.EnableRoot()
  if device.HasRoot():
    # Disable Marshmallow's Verity security feature
    if device.build_version_sdk >= version_codes.MARSHMALLOW:
      logger.info('Disabling Verity on %s', device.serial)
      device.adb.DisableVerity()
      device.Reboot()
      device.WaitUntilFullyBooted()
      device.EnableRoot()

    device.adb.Remount()
    device.RunShellCommand(['stop'], check_return=True)
    for system_app in system_app_remove_list:
      _RemoveSystemApp(device, system_app)
    device.RunShellCommand(['start'], check_return=True)
  else:
    raise device_errors.CommandFailedError(
        'Failed to remove system apps from non-rooted device', str(device))


def _ConfigureLocalProperties(device, java_debug=True):
  """Set standard readonly testing device properties prior to reboot."""
  local_props = [
      'persist.sys.usb.config=adb',
      'ro.monkey=1',
      'ro.test_harness=1',
      'ro.audio.silent=1',
      'ro.setupwizard.mode=DISABLED',
      ]
  if java_debug:
    local_props.append(
        '%s=all' % device_utils.DeviceUtils.JAVA_ASSERT_PROPERTY)
    local_props.append('debug.checkjni=1')
  try:
    device.WriteFile(
        device.LOCAL_PROPERTIES_PATH,
        '\n'.join(local_props), as_root=True)
    # Android will not respect the local props file if it is world writable.
    device.RunShellCommand(
        ['chmod', '644', device.LOCAL_PROPERTIES_PATH],
        as_root=True, check_return=True)
  except device_errors.CommandFailedError:
    logger.exception('Failed to configure local properties.')


def FinishProvisioning(device):
  # The lockscreen can't be disabled on user builds, so send a keyevent
  # to unlock it.
  if device.IsUserBuild():
    device.SendKeyEvent(keyevent.KEYCODE_MENU)


def WaitForCharge(device, min_battery_level):
  battery = battery_utils.BatteryUtils(device)
  try:
    battery.ChargeDeviceToLevel(min_battery_level)
  except device_errors.DeviceChargingError:
    device.Reboot()
    battery.ChargeDeviceToLevel(min_battery_level)


def WaitForTemperature(device, max_battery_temp):
  try:
    battery = battery_utils.BatteryUtils(device)
    battery.LetBatteryCoolToTemperature(max_battery_temp)
  except device_errors.CommandFailedError:
    logger.exception('Unable to let battery cool to specified temperature.')


def SetDate(device):
  def _set_and_verify_date():
    if device.build_version_sdk >= version_codes.MARSHMALLOW:
      date_format = '%m%d%H%M%Y.%S'
      set_date_command = ['date', '-u']
      get_date_command = ['date', '-u']
    else:
      date_format = '%Y%m%d.%H%M%S'
      set_date_command = ['date', '-s']
      get_date_command = ['date']

    # TODO(jbudorick): This is wrong on pre-M devices -- get/set are
    # dealing in local time, but we're setting based on GMT.
    strgmtime = time.strftime(date_format, time.gmtime())
    set_date_command.append(strgmtime)
    device.RunShellCommand(set_date_command, as_root=True, check_return=True)

    get_date_command.append('+"%Y%m%d.%H%M%S"')
    device_time = device.RunShellCommand(
        get_date_command, check_return=True,
        as_root=True, single_line=True).replace('"', '')
    device_time = datetime.datetime.strptime(device_time, "%Y%m%d.%H%M%S")
    correct_time = datetime.datetime.strptime(strgmtime, date_format)
    tdelta = (correct_time - device_time).seconds
    if tdelta <= 1:
      logger.info('Date/time successfully set on %s', device)
      return True
    else:
      logger.error('Date mismatch. Device: %s Correct: %s',
                   device_time.isoformat(), correct_time.isoformat())
      return False

  # Sometimes the date is not set correctly on the devices. Retry on failure.
  if device.IsUserBuild():
    # TODO(bpastene): Figure out how to set the date & time on user builds.
    pass
  else:
    if not timeout_retry.WaitFor(
        _set_and_verify_date, wait_period=1, max_tries=2):
      raise device_errors.CommandFailedError(
          'Failed to set date & time.', device_serial=str(device))
    device.EnableRoot()
    device.BroadcastIntent(
        intent.Intent(action='android.intent.action.TIME_SET'))


def LogDeviceProperties(device):
  props = device.RunShellCommand(['getprop'], check_return=True)
  for prop in props:
    logger.info('  %s', prop)


def CheckExternalStorage(device):
  """Checks that storage is writable and if not makes it writable.

  Arguments:
    device: The device to check.
  """
  try:
    with device_temp_file.DeviceTempFile(
        device.adb, suffix='.sh', dir=device.GetExternalStoragePath()) as f:
      device.WriteFile(f.name, 'test')
  except device_errors.CommandFailedError:
    logger.info('External storage not writable. Remounting / as RW')
    device.RunShellCommand(['mount', '-o', 'remount,rw', '/'],
                           check_return=True, as_root=True)
    device.EnableRoot()
    with device_temp_file.DeviceTempFile(
        device.adb, suffix='.sh', dir=device.GetExternalStoragePath()) as f:
      device.WriteFile(f.name, 'test')


def main(raw_args):
  # Recommended options on perf bots:
  # --disable-network
  #     TODO(tonyg): We eventually want network on. However, currently radios
  #     can cause perfbots to drain faster than they charge.
  # --min-battery-level 95
  #     Some perf bots run benchmarks with USB charging disabled which leads
  #     to gradual draining of the battery. We must wait for a full charge
  #     before starting a run in order to keep the devices online.

  parser = argparse.ArgumentParser(
      description='Provision Android devices with settings required for bots.')
  parser.add_argument(
      '--adb-key-files', type=str, nargs='+',
      help='list of adb keys to push to device')
  parser.add_argument(
      '--adb-path',
      help='Absolute path to the adb binary to use.')
  parser.add_argument('--blacklist-file', help='Device blacklist JSON file.')
  parser.add_argument(
      '-d', '--device', metavar='SERIAL', action='append', dest='devices',
      help='the serial number of the device to be provisioned '
           '(the default is to provision all devices attached)')
  parser.add_argument(
      '--disable-location', action='store_true',
      help='disable Google location services on devices')
  parser.add_argument(
      '--disable-mock-location', action='store_true', default=False,
      help='Set ALLOW_MOCK_LOCATION to false')
  parser.add_argument(
      '--disable-network', action='store_true',
      help='disable network access on devices')
  parser.add_argument(
      '--disable-java-debug', action='store_false',
      dest='enable_java_debug', default=True,
      help='disable Java property asserts and JNI checking')
  parser.add_argument(
      '--disable-system-chrome', action='store_true',
      help='Disable the system chrome from devices.')
  parser.add_argument(
      '--emulators', action='store_true',
      help='provision only emulators and ignore usb devices '
           '(this will not wipe emulators)')
  parser.add_argument(
      '--max-battery-temp', type=int, metavar='NUM',
      help='Wait for the battery to have this temp or lower.')
  parser.add_argument(
      '--min-battery-level', type=int, metavar='NUM',
      help='wait for the device to reach this minimum battery'
           ' level before trying to continue')
  parser.add_argument(
      '--output-device-blacklist',
      help='Json file to output the device blacklist.')
  parser.add_argument(
      '--reboot-timeout', metavar='SECS', type=int,
      help='when wiping the device, max number of seconds to'
           ' wait after each reboot '
           '(default: %s)' % _DEFAULT_TIMEOUTS.HELP_TEXT)
  parser.add_argument(
      '--remove-system-apps', nargs='*', dest='system_app_remove_list',
      help='the names of system apps to remove')
  parser.add_argument(
      '--remove-system-webview', action='store_true',
      help='Remove the system webview from devices.')
  parser.add_argument(
      '--skip-wipe', action='store_true', default=False,
      help='do not wipe device data during provisioning')
  parser.add_argument(
      '-v', '--verbose', action='count', default=1,
      help='Log more information.')

  # No-op arguments for compatibility with build/android/provision_devices.py.
  # TODO(jbudorick): Remove these once all callers have stopped using them.
  parser.add_argument(
      '--chrome-specific-wipe', action='store_true',
      help=argparse.SUPPRESS)
  parser.add_argument(
      '--phase', action='append',
      help=argparse.SUPPRESS)
  parser.add_argument(
      '-r', '--auto-reconnect', action='store_true',
      help=argparse.SUPPRESS)
  parser.add_argument(
      '-t', '--target',
      help=argparse.SUPPRESS)

  args = parser.parse_args(raw_args)

  run_tests_helper.SetLogLevel(args.verbose)

  devil_dynamic_config = devil_env.EmptyConfig()
  if args.adb_path:
    devil_dynamic_config['dependencies'].update(
        devil_env.LocalConfigItem(
            'adb', devil_env.GetPlatform(), args.adb_path))

  devil_env.config.Initialize(configs=[devil_dynamic_config])

  try:
    return ProvisionDevices(
        args.devices,
        args.blacklist_file,
        adb_key_files=args.adb_key_files,
        disable_location=args.disable_location,
        disable_mock_location=args.disable_mock_location,
        disable_network=args.disable_network,
        disable_system_chrome=args.disable_system_chrome,
        emulators=args.emulators,
        enable_java_debug=args.enable_java_debug,
        max_battery_temp=args.max_battery_temp,
        min_battery_level=args.min_battery_level,
        output_device_blacklist=args.output_device_blacklist,
        reboot_timeout=args.reboot_timeout,
        remove_system_webview=args.remove_system_webview,
        system_app_remove_list=args.system_app_remove_list,
        wipe=not args.skip_wipe and not args.emulators)
  except (device_errors.DeviceUnreachableError, device_errors.NoDevicesError):
    logging.exception('Unable to provision local devices.')
    return exit_codes.INFRA


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
