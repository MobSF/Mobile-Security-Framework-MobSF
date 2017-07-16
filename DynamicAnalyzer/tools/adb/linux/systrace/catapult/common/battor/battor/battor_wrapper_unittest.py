# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import dependency_manager
import logging
import mock
import subprocess
import unittest

from battor import battor_error
from battor import battor_wrapper
from devil.utils import battor_device_mapping
from devil.utils import find_usb_devices

import serial
from serial.tools import list_ports


class DependencyManagerMock(object):
  def __init__(self, _):
    self._fetch_return = 'path'
    self._version_return = 'cbaa843'

  def FetchPath(self, _, *unused):
    del unused
    return self._fetch_return

  def FetchPathWithVersion(self, _, *unused):
    del unused
    return self._fetch_return, self._version_return

class PopenMock(object):
  def __init__(self, *unused):
    pass

  def poll(self):
    pass

  def kill(self):
    pass


class IsBattOrConnectedTest(unittest.TestCase):
  def setUp(self):
    # Windows monkey patches.
    self._serial_tools_return = []
    self._comports = serial.tools.list_ports.comports
    serial.tools.list_ports.comports = lambda: self._serial_tools_return

    # Linux/Android monkey patches.
    self._generate_serial_map_return = {}
    self._generate_serial_map = battor_device_mapping.GenerateSerialMap
    battor_device_mapping.GenerateSerialMap = (
        lambda: self._generate_serial_map_return)

    self._read_serial_map_file_return = {}
    self._read_serial_map_file = battor_device_mapping.ReadSerialMapFile
    battor_device_mapping.ReadSerialMapFile = (
        lambda f: self._read_serial_map_file_return)

    self._get_bus_number_to_device_tree_map = (
        find_usb_devices.GetBusNumberToDeviceTreeMap)
    find_usb_devices.GetBusNumberToDeviceTreeMap = lambda fast=None: None

    self._get_battor_list_return = []
    self._get_battor_list = battor_device_mapping.GetBattOrList
    battor_device_mapping.GetBattOrList = lambda x: self._get_battor_list_return

  def tearDown(self):
    serial.tools.list_ports.comports = self._comports
    battor_device_mapping.GenerateSerialMap = self._generate_serial_map
    battor_device_mapping.ReadSerialMapFile = self._read_serial_map_file
    find_usb_devices.GetBusNumberToDeviceTreeMap = (
        self._get_bus_number_to_device_tree_map)
    battor_device_mapping.GetBattOrList = self._get_battor_list

  def forceException(self):
    raise NotImplementedError

  def testAndroidWithBattOr(self):
    self._generate_serial_map_return = {'abc': '123'}
    self.assertTrue(battor_wrapper.IsBattOrConnected('android', 'abc'))

  def testAndroidWithoutMatchingBattOr(self):
    self._generate_serial_map_return = {'notabc': 'not123'}
    self.assertFalse(battor_wrapper.IsBattOrConnected('android', 'abc'))

  def testAndroidNoDevicePassed(self):
    with self.assertRaises(ValueError):
      battor_wrapper.IsBattOrConnected('android')

  def testAndroidWithMapAndFile(self):
    device_map = {'abc': '123'}
    battor_device_mapping.ReadSerialMapFile = self.forceException
    self.assertTrue(
        battor_wrapper.IsBattOrConnected('android', android_device='abc',
                                        android_device_map=device_map,
                                        android_device_file='file'))

  def testAndroidWithMap(self):
    self.assertTrue(
        battor_wrapper.IsBattOrConnected('android', android_device='abc',
                                        android_device_map={'abc', '123'}))

  def testAndroidWithFile(self):
    self._read_serial_map_file_return = {'abc': '123'}
    self.assertTrue(
      battor_wrapper.IsBattOrConnected('android', android_device='abc',
                                      android_device_file='file'))

  def testLinuxWithBattOr(self):
    self._get_battor_list_return = ['battor']
    self.assertTrue(battor_wrapper.IsBattOrConnected('linux'))

  def testLinuxWithoutBattOr(self):
    self._get_battor_list_return = []
    self.assertFalse(battor_wrapper.IsBattOrConnected('linux'))

  def testMacWithBattOr(self):
    self._serial_tools_return = [('/dev/tty.usbserial-MAA', 'BattOr v3.3', '')]
    self.assertTrue(battor_wrapper.IsBattOrConnected('mac'))

  def testMacWithoutBattOr(self):
    self._serial_tools_return = [('/dev/tty.usbserial-MAA', 'not_one', '')]
    self.assertFalse(battor_wrapper.IsBattOrConnected('mac'))

  def testWinWithBattOr(self):
    self._serial_tools_return = [('COM4', 'USB Serial Port', '')]
    self.assertTrue(battor_wrapper.IsBattOrConnected('win'))

  def testWinWithoutBattOr(self):
    self._get_battor_list_return = []
    self.assertFalse(battor_wrapper.IsBattOrConnected('win'))


class BattOrWrapperTest(unittest.TestCase):
  def setUp(self):
    self._battor = None
    self._is_battor = True
    self._battor_list = ['battor1']
    self._should_pass = True
    self._fake_map = {'battor1': 'device1'}
    self._fake_return_code = None
    self._fake_battor_return = 'Done.\n'

    self._get_battor_path_from_phone_serial = (
        battor_device_mapping.GetBattOrPathFromPhoneSerial)
    self._get_bus_number_to_device_tree_map = (
        find_usb_devices.GetBusNumberToDeviceTreeMap)
    self._dependency_manager = dependency_manager.DependencyManager
    self._get_battor_list = battor_device_mapping.GetBattOrList
    self._is_battor = battor_device_mapping.IsBattOr
    self._generate_serial_map = battor_device_mapping.GenerateSerialMap
    self._serial_tools = serial.tools.list_ports.comports

    battor_device_mapping.GetBattOrPathFromPhoneSerial = (
        lambda x, serial_map_file=None, serial_map=None: x + '_battor')
    find_usb_devices.GetBusNumberToDeviceTreeMap = lambda fast=False: True
    dependency_manager.DependencyManager = DependencyManagerMock
    battor_device_mapping.GetBattOrList = lambda x: self._battor_list
    battor_device_mapping.IsBattOr = lambda x, y: self._is_battor
    battor_device_mapping.GenerateSerialMap = lambda: self._fake_map
    serial.tools.list_ports.comports = lambda: [('COM4', 'USB Serial Port', '')]

    self._subprocess_check_output_code = 0
    def subprocess_check_output_mock(*unused):
      if self._subprocess_check_output_code != 0:
        raise subprocess.CalledProcessError(None, None)
      return 0
    self._subprocess_check_output = subprocess.check_output
    subprocess.check_output = subprocess_check_output_mock

  def tearDown(self):
    battor_device_mapping.GetBattOrPathFromPhoneSerial = (
        self._get_battor_path_from_phone_serial)
    find_usb_devices.GetBusNumberToDeviceTreeMap = (
        self._get_bus_number_to_device_tree_map)
    dependency_manager.DependencyManager = self._dependency_manager
    battor_device_mapping.GetBattOrList = self._get_battor_list
    battor_device_mapping.IsBattOr = self._is_battor
    battor_device_mapping.GenerateSerialMap = self._generate_serial_map
    serial.tools.list_ports.comports = self._serial_tools
    subprocess.check_output = self._subprocess_check_output

  def _DefaultBattOrReplacements(self):
    battor_wrapper.DEFAULT_SHELL_CLOSE_TIMEOUT_S = .1
    self._battor._StartShellImpl = lambda *unused: PopenMock()
    self._battor.GetShellReturnCode = lambda *unused: self._fake_return_code
    self._battor._SendBattOrCommandImpl = lambda x: self._fake_battor_return
    self._battor._StopTracingImpl = lambda *unused: (self._fake_battor_return,
                                                     None)

  def testBadPlatform(self):
    with self.assertRaises(battor_error.BattOrError):
      self._battor = battor_wrapper.BattOrWrapper('unknown')

  def testInitAndroidWithBattOr(self):
    self._battor = battor_wrapper.BattOrWrapper('android', android_device='abc')
    self.assertEquals(self._battor._battor_path, 'abc_battor')

  def testInitAndroidWithoutBattOr(self):
    self._battor_list = []
    self._fake_map = {}
    battor_device_mapping.GetBattOrPathFromPhoneSerial = (
        self._get_battor_path_from_phone_serial)
    with self.assertRaises(battor_error.BattOrError):
      self._battor = battor_wrapper.BattOrWrapper('android',
                                                  android_device='abc')

  def testInitBattOrPathIsBattOr(self):
    battor_path = 'battor/path/here'
    self._battor = battor_wrapper.BattOrWrapper(
        'android', android_device='abc', battor_path=battor_path)
    self.assertEquals(self._battor._battor_path, battor_path)

  def testInitNonAndroidWithBattOr(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self.assertEquals(self._battor._battor_path, 'COM4')

  def testInitNonAndroidWithMultipleBattOr(self):
    self._battor_list.append('battor2')
    with self.assertRaises(battor_error.BattOrError):
      self._battor = battor_wrapper.BattOrWrapper('linux')

  def testInitNonAndroidWithoutBattOr(self):
    self._battor_list = []
    serial.tools.list_ports.comports = lambda: [('COM4', 'None', '')]
    with self.assertRaises(battor_error.BattOrError):
      self._battor = battor_wrapper.BattOrWrapper('win')

  def testStartShellPass(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self.assertIsNotNone(self._battor._battor_shell)

  def testStartShellDoubleStart(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    with self.assertRaises(AssertionError):
      self._battor.StartShell()

  def testStartShellFail(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.GetShellReturnCode = lambda *unused: 1
    with self.assertRaises(AssertionError):
      self._battor.StartShell()

  def testStartTracingPass(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.StartTracing()
    self.assertTrue(self._battor._tracing)

  def testStartTracingDoubleStart(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.StartTracing()
    with self.assertRaises(AssertionError):
      self._battor.StartTracing()

  def testStartTracingCommandFails(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor._SendBattOrCommandImpl = lambda *unused: 'Fail.\n'
    self._battor.StartShell()
    with self.assertRaises(battor_error.BattOrError):
      self._battor.StartTracing()

  def testStopTracingPass(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.StartTracing()
    self._battor.GetShellReturnCode = lambda *unused: 0
    self._battor.StopTracing()
    self.assertFalse(self._battor._tracing)

  def testStopTracingNotRunning(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    with self.assertRaises(AssertionError):
      self._battor.StopTracing()

  def testFlashFirmwarePass(self):
    self._battor = battor_wrapper.BattOrWrapper('linux')
    self._DefaultBattOrReplacements()
    self.assertTrue(self._battor.FlashFirmware('hex_path', 'config_path'))

  def testFlashFirmwareFail(self):
    self._battor = battor_wrapper.BattOrWrapper('linux')
    self._DefaultBattOrReplacements()
    self._subprocess_check_output_code = 1
    with self.assertRaises(battor_wrapper.BattOrFlashError):
      self._battor.FlashFirmware('hex_path', 'config_path')

  def testFlashFirmwarePlatformNotSupported(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor._target_platform = 'unsupported_platform'
    self.assertFalse(self._battor.FlashFirmware('hex_path', 'config_path'))

  def testFlashFirmwareShellRunning(self):
    self._battor = battor_wrapper.BattOrWrapper('linux')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    with self.assertRaises(AssertionError):
      self._battor.FlashFirmware('hex_path', 'config_path')

  def testGetFirmwareGitHashNotRunning(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    with self.assertRaises(AssertionError):
      self._battor.GetFirmwareGitHash()

  def testGetFirmwareGitHashPass(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.GetFirmwareGitHash = lambda: 'cbaa843'
    self.assertTrue(isinstance(self._battor.GetFirmwareGitHash(), basestring))

  def testStopShellPass(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._fake_return_code = 0
    self._battor.StopShell()
    self.assertIsNone(self._battor._battor_shell)

  @mock.patch('time.sleep', mock.Mock)
  def testStopShellTimeOutAndKill(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.StopShell()
    self.assertIsNone(self._battor._battor_shell)

  def testStopShellNotStarted(self):
    self._battor = battor_wrapper.BattOrWrapper('win')
    self._DefaultBattOrReplacements()
    with self.assertRaises(AssertionError):
      self._battor.StopShell()

  @mock.patch('time.sleep', mock.Mock)
  def testFlashBattOrSameGitHash(self):
    self._battor = battor_wrapper.BattOrWrapper('linux')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.GetFirmwareGitHash = lambda: 'cbaa843'
    dependency_manager.DependencyManager._version_return = 'cbaa843'
    self.assertFalse(self._battor._FlashBattOr())

  @mock.patch('time.sleep', mock.Mock)
  def testFlashBattOrDifferentGitHash(self):
    self._battor = battor_wrapper.BattOrWrapper('linux')
    self._DefaultBattOrReplacements()
    self._battor.StartShell()
    self._battor.GetFirmwareGitHash = lambda: 'bazz732'
    dependency_manager.DependencyManager._version_return = 'cbaa843'
    self.assertTrue(self._battor._FlashBattOr())


if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
