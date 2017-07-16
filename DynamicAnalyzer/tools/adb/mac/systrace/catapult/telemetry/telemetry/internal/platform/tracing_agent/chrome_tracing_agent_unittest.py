# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import platform
import stat
import unittest

from telemetry import decorators
from telemetry.internal.platform.tracing_agent import chrome_tracing_agent
from telemetry.internal.platform.tracing_agent import (
    chrome_tracing_devtools_manager)
from telemetry.timeline import tracing_config
from telemetry.core import cros_interface
from telemetry.testing import options_for_unittests


from devil.android import device_utils


class FakeTracingControllerBackend(object):
  def __init__(self):
    self.is_tracing_running = False


class FakePlatformBackend(object):
  def __init__(self):
    self.tracing_controller_backend = FakeTracingControllerBackend()

  def GetOSName(self):
    return ''

class FakeAndroidPlatformBackend(FakePlatformBackend):
  def __init__(self):
    super(FakeAndroidPlatformBackend, self).__init__()
    devices = device_utils.DeviceUtils.HealthyDevices(None)
    self.device = devices[0]

  def GetOSName(self):
    return 'android'

class FakeCrOSPlatformBackend(FakePlatformBackend):
  def __init__(self):
    super(FakeCrOSPlatformBackend, self).__init__()
    remote = options_for_unittests.GetCopy().cros_remote
    remote_ssh_port = options_for_unittests.GetCopy().cros_remote_ssh_port
    self.cri = cros_interface.CrOSInterface(
        remote, remote_ssh_port,
        options_for_unittests.GetCopy().cros_ssh_identity)

  def GetOSName(self):
    return 'chromeos'

class FakeDesktopPlatformBackend(FakePlatformBackend):
  def GetOSName(self):
    system = platform.system()
    if system == 'Linux':
      return 'linux'
    if system == 'Darwin':
      return 'mac'
    if system == 'Windows':
      return 'win'


class FakeContextMap(object):
  def __init__(self, contexts):
    self.contexts = contexts


class FakeDevtoolsClient(object):
  def __init__(self, remote_port):
    self.is_alive = True
    self.is_tracing_running = False
    self.remote_port = remote_port
    self.will_raise_exception_in_stop_tracing = False
    self.collected = False

  def IsAlive(self):
    return self.is_alive

  def StartChromeTracing(self, trace_options, timeout=10):
    del trace_options, timeout  # unused
    self.is_tracing_running = True

  def StopChromeTracing(self):
    self.is_tracing_running = False
    if self.will_raise_exception_in_stop_tracing:
      raise Exception

  def CollectChromeTracingData(self, trace_data_builder, timeout=30):
    del trace_data_builder  # unused
    del timeout # unused
    self.collected = True

  def IsChromeTracingSupported(self):
    return True

  def GetUpdatedInspectableContexts(self):
    return FakeContextMap([])


class ChromeTracingAgentTest(unittest.TestCase):
  def setUp(self):
    self.platform1 = FakePlatformBackend()
    self.platform2 = FakePlatformBackend()
    self.platform3 = FakePlatformBackend()

  def StartTracing(self, platform_backend, enable_chrome_trace=True):
    assert chrome_tracing_agent.ChromeTracingAgent.IsSupported(platform_backend)
    agent = chrome_tracing_agent.ChromeTracingAgent(platform_backend)
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = enable_chrome_trace
    config.chrome_trace_config.category_filter.AddIncludedCategory('foo')
    agent._platform_backend.tracing_controller_backend.is_tracing_running = True
    agent._test_config = config
    agent.StartAgentTracing(config, 10)
    return agent

  def FlushTracing(self, agent):
    agent.FlushAgentTracing(agent._test_config, 10, None)

  def StopTracing(self, agent):
    agent._platform_backend.tracing_controller_backend.is_tracing_running = (
        False)
    agent.StopAgentTracing()
    agent.CollectAgentTraceData(None)

  def testRegisterDevtoolsClient(self):
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(1), self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(2), self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(3), self.platform1)

    tracing_agent_of_platform1 = self.StartTracing(self.platform1)

    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(4), self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(5), self.platform2)

    self.StopTracing(tracing_agent_of_platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        FakeDevtoolsClient(6), self.platform1)

  def testIsSupportWithoutStartupTracingSupport(self):
    self.assertFalse(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform1))
    self.assertFalse(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform2))
    self.assertFalse(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform3))

    devtool1 = FakeDevtoolsClient(1)
    devtool2 = FakeDevtoolsClient(2)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool1, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool2, self.platform2)
    devtool2.is_alive = False

    # Chrome tracing is only supported on platform 1 since only platform 1 has
    # an alive devtool.
    self.assertTrue(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform1))
    self.assertFalse(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform2))
    self.assertFalse(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(self.platform3))

  @decorators.Enabled('linux', 'mac', 'win')
  def testIsSupportOnDesktopPlatform(self):
    # Chrome tracing is always supported on desktop platforms because of startup
    # tracing.
    desktop_platform = FakeDesktopPlatformBackend()
    self.assertTrue(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(desktop_platform))

    devtool = FakeDevtoolsClient(1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool, desktop_platform)
    self.assertTrue(
        chrome_tracing_agent.ChromeTracingAgent.IsSupported(desktop_platform))

  def testStartAndStopTracing(self):
    devtool1 = FakeDevtoolsClient(1)
    devtool2 = FakeDevtoolsClient(2)
    devtool3 = FakeDevtoolsClient(3)
    devtool4 = FakeDevtoolsClient(2)
    # Register devtools 1, 2, 3 on platform1 and devtool 4 on platform 2
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool1, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool2, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool3, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool4, self.platform2)
    devtool2.is_alive = False

    tracing_agent1 = self.StartTracing(self.platform1)
    with self.assertRaises(chrome_tracing_agent.ChromeTracingStartedError):
      self.StartTracing(self.platform1)

    self.assertTrue(devtool1.is_tracing_running)
    self.assertFalse(devtool2.is_tracing_running)
    self.assertTrue(devtool3.is_tracing_running)
    # Devtool 4 shouldn't have tracing started although it has the same remote
    # port as devtool 2
    self.assertFalse(devtool4.is_tracing_running)


    self.assertFalse(devtool1.collected)
    self.StopTracing(tracing_agent1)
    self.assertTrue(devtool1.collected)
    self.assertFalse(devtool1.is_tracing_running)
    self.assertFalse(devtool2.is_tracing_running)
    self.assertFalse(devtool3.is_tracing_running)
    self.assertFalse(devtool4.is_tracing_running)

    # Test that it should be ok to start & stop tracing on platform1 again.
    tracing_agent1 = self.StartTracing(self.platform1)
    self.StopTracing(tracing_agent1)

    tracing_agent2 = self.StartTracing(self.platform2)
    self.assertTrue(devtool4.is_tracing_running)
    self.assertFalse(devtool4.collected)
    self.StopTracing(tracing_agent2)
    self.assertFalse(devtool4.is_tracing_running)
    self.assertTrue(devtool4.collected)

  def testFlushTracing(self):
    devtool1 = FakeDevtoolsClient(1)
    devtool2 = FakeDevtoolsClient(2)
    devtool3 = FakeDevtoolsClient(3)
    devtool4 = FakeDevtoolsClient(2)

    # Register devtools 1, 2, 3 on platform1 and devtool 4 on platform 2.
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool1, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool2, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool3, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool4, self.platform2)
    devtool2.is_alive = False

    tracing_agent1 = self.StartTracing(self.platform1)

    self.assertTrue(devtool1.is_tracing_running)
    self.assertFalse(devtool2.is_tracing_running)
    self.assertTrue(devtool3.is_tracing_running)
    # Devtool 4 shouldn't have tracing started although it has the same remote
    # port as devtool 2.
    self.assertFalse(devtool4.is_tracing_running)

    for _ in xrange(5):
      self.FlushTracing(tracing_agent1)
      self.assertTrue(devtool1.is_tracing_running)
      self.assertFalse(devtool2.is_tracing_running)
      self.assertTrue(devtool3.is_tracing_running)
      self.assertFalse(devtool4.is_tracing_running)

    self.StopTracing(tracing_agent1)
    self.assertFalse(devtool1.is_tracing_running)
    self.assertFalse(devtool2.is_tracing_running)
    self.assertFalse(devtool3.is_tracing_running)
    self.assertFalse(devtool4.is_tracing_running)

    # Test that it is ok to start, flush & stop tracing on platform1 again.
    tracing_agent1 = self.StartTracing(self.platform1)
    self.FlushTracing(tracing_agent1)
    self.StopTracing(tracing_agent1)

    tracing_agent2 = self.StartTracing(self.platform2)
    self.assertTrue(devtool4.is_tracing_running)
    self.FlushTracing(tracing_agent2)
    self.assertTrue(devtool4.is_tracing_running)
    self.StopTracing(tracing_agent2)
    self.assertFalse(devtool4.is_tracing_running)

  def testExceptionRaisedInStopTracing(self):
    devtool1 = FakeDevtoolsClient(1)
    devtool2 = FakeDevtoolsClient(2)
    # Register devtools 1, 2 on platform 1
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool1, self.platform1)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool2, self.platform1)
    tracing_agent1 = self.StartTracing(self.platform1)

    self.assertTrue(devtool1.is_tracing_running)
    self.assertTrue(devtool2.is_tracing_running)

    devtool1.will_raise_exception_in_stop_tracing = True
    with self.assertRaises(chrome_tracing_agent.ChromeTracingStoppedError):
      self.StopTracing(tracing_agent1)
    # Tracing is stopped on both devtools clients even if there is exception.
    self.assertIsNone(tracing_agent1.trace_config)
    self.assertFalse(devtool1.is_tracing_running)
    self.assertFalse(devtool2.is_tracing_running)

    devtool1.is_alive = False
    devtool2.is_alive = False
    # Register devtools 3 on platform 1 should not raise any exception.
    devtool3 = FakeDevtoolsClient(3)
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        devtool3, self.platform1)

    # Start & Stop tracing on platform 1 should work just fine.
    tracing_agent2 = self.StartTracing(self.platform1)
    self.StopTracing(tracing_agent2)

  @decorators.Enabled('android')
  def testCreateAndRemoveTraceConfigFileOnAndroid(self):
    platform_backend = FakeAndroidPlatformBackend()
    agent = chrome_tracing_agent.ChromeTracingAgent(platform_backend)
    self.assertIsNone(agent.trace_config_file)

    config = tracing_config.TracingConfig()
    agent._CreateTraceConfigFile(config)
    self.assertIsNotNone(agent.trace_config_file)
    self.assertTrue(platform_backend.device.PathExists(agent.trace_config_file))
    config_file_str = platform_backend.device.ReadFile(agent.trace_config_file,
                                                       as_root=True)
    self.assertEqual(agent._CreateTraceConfigFileString(config),
                     config_file_str.strip())

    config_file_path = agent.trace_config_file
    agent._RemoveTraceConfigFile()
    self.assertFalse(platform_backend.device.PathExists(config_file_path))
    self.assertIsNone(agent.trace_config_file)
    # robust to multiple file removal
    agent._RemoveTraceConfigFile()
    self.assertFalse(platform_backend.device.PathExists(config_file_path))
    self.assertIsNone(agent.trace_config_file)

  @decorators.Enabled('chromeos')
  def testCreateAndRemoveTraceConfigFileOnCrOS(self):
    platform_backend = FakeCrOSPlatformBackend()
    cri = platform_backend.cri
    agent = chrome_tracing_agent.ChromeTracingAgent(platform_backend)
    self.assertIsNone(agent.trace_config_file)

    config = tracing_config.TracingConfig()
    agent._CreateTraceConfigFile(config)
    self.assertIsNotNone(agent.trace_config_file)
    self.assertTrue(cri.FileExistsOnDevice(agent.trace_config_file))
    config_file_str = cri.GetFileContents(agent.trace_config_file)
    self.assertEqual(agent._CreateTraceConfigFileString(config),
                     config_file_str.strip())

    config_file_path = agent.trace_config_file
    agent._RemoveTraceConfigFile()
    self.assertFalse(cri.FileExistsOnDevice(config_file_path))
    self.assertIsNone(agent.trace_config_file)
    # robust to multiple file removal
    agent._RemoveTraceConfigFile()
    self.assertFalse(cri.FileExistsOnDevice(config_file_path))
    self.assertIsNone(agent.trace_config_file)

  @decorators.Enabled('linux', 'mac', 'win')
  def testCreateAndRemoveTraceConfigFileOnDesktop(self):
    platform_backend = FakeDesktopPlatformBackend()
    agent = chrome_tracing_agent.ChromeTracingAgent(platform_backend)
    self.assertIsNone(agent.trace_config_file)

    config = tracing_config.TracingConfig()
    agent._CreateTraceConfigFile(config)
    self.assertIsNotNone(agent.trace_config_file)
    self.assertTrue(os.path.exists(agent.trace_config_file))
    self.assertTrue(os.stat(agent.trace_config_file).st_mode & stat.S_IROTH)
    with open(agent.trace_config_file, 'r') as f:
      config_file_str = f.read()
      self.assertEqual(agent._CreateTraceConfigFileString(config),
                       config_file_str.strip())

    config_file_path = agent.trace_config_file
    agent._RemoveTraceConfigFile()
    self.assertFalse(os.path.exists(config_file_path))
    self.assertIsNone(agent.trace_config_file)
    # robust to multiple file removal
    agent._RemoveTraceConfigFile()
    self.assertFalse(os.path.exists(config_file_path))
    self.assertIsNone(agent.trace_config_file)
