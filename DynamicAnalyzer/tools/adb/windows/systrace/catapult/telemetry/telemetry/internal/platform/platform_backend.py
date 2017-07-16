# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import weakref

from battor import battor_wrapper
from telemetry.internal import forwarders
from telemetry.internal.forwarders import do_nothing_forwarder
from telemetry.internal.platform import network_controller_backend
from telemetry.internal.platform import tracing_controller_backend


# pylint: disable=unused-argument

class PlatformBackend(object):

  def __init__(self, device=None):
    """ Initalize an instance of PlatformBackend from a device optionally.
      Call sites need to use SupportsDevice before intialization to check
      whether this platform backend supports the device.
      If device is None, this constructor returns the host platform backend
      which telemetry is running on.

      Args:
        device: an instance of telemetry.core.platform.device.Device.
    """
    if device and not self.SupportsDevice(device):
      raise ValueError('Unsupported device: %s' % device.name)
    self._platform = None
    self._running_browser_backends = weakref.WeakSet()
    self._network_controller_backend = None
    self._tracing_controller_backend = None
    self._forwarder_factory = None

  def InitPlatformBackend(self):
    self._network_controller_backend = (
        network_controller_backend.NetworkControllerBackend(self))
    self._tracing_controller_backend = (
        tracing_controller_backend.TracingControllerBackend(self))

  @classmethod
  def IsPlatformBackendForHost(cls):
    """ Returns whether this platform backend is the platform backend to be used
    for the host device which telemetry is running on. """
    return False

  @classmethod
  def SupportsDevice(cls, device):
    """ Returns whether this platform backend supports intialization from the
    device. """
    return False

  @classmethod
  def CreatePlatformForDevice(cls, device, finder_options):
    raise NotImplementedError

  def SetPlatform(self, platform):
    assert self._platform == None
    self._platform = platform

  @property
  def platform(self):
    return self._platform

  @property
  def is_host_platform(self):
    return self._platform.is_host_platform

  @property
  def running_browser_backends(self):
    return list(self._running_browser_backends)

  @property
  def network_controller_backend(self):
    return self._network_controller_backend

  @property
  def tracing_controller_backend(self):
    return self._tracing_controller_backend

  @property
  def forwarder_factory(self):
    if not self._forwarder_factory:
      self._forwarder_factory = do_nothing_forwarder.DoNothingForwarderFactory()
    return self._forwarder_factory

  def GetPortPairForForwarding(self, local_port):
    return forwarders.PortPair(local_port=local_port, remote_port=local_port)

  def GetRemotePort(self, port):
    return port

  def GetSystemLog(self):
    return None

  def DidCreateBrowser(self, browser, browser_backend):
    browser_options = browser_backend.browser_options
    self.SetFullPerformanceModeEnabled(browser_options.full_performance_mode)

  def DidStartBrowser(self, browser, browser_backend):
    assert browser not in self._running_browser_backends
    self._running_browser_backends.add(browser_backend)

  def WillCloseBrowser(self, browser, browser_backend):
    is_last_browser = len(self._running_browser_backends) <= 1
    if is_last_browser:
      self.SetFullPerformanceModeEnabled(False)

    self._running_browser_backends.discard(browser_backend)

  def IsDisplayTracingSupported(self):
    return False

  def StartDisplayTracing(self):
    """Start gathering a trace with frame timestamps close to physical
    display."""
    raise NotImplementedError()

  def StopDisplayTracing(self):
    """Stop gathering a trace with frame timestamps close to physical display.

    Returns a raw tracing events that contains the timestamps of physical
    display.
    """
    raise NotImplementedError()

  def SetFullPerformanceModeEnabled(self, enabled):
    pass

  def CanMonitorThermalThrottling(self):
    return False

  def IsThermallyThrottled(self):
    raise NotImplementedError()

  def HasBeenThermallyThrottled(self):
    raise NotImplementedError()

  def GetSystemCommitCharge(self):
    raise NotImplementedError()

  def GetSystemTotalPhysicalMemory(self):
    raise NotImplementedError()

  def GetCpuStats(self, pid):
    return {}

  def GetCpuTimestamp(self):
    return {}

  def PurgeUnpinnedMemory(self):
    pass

  def GetMemoryStats(self, pid):
    return {}

  def GetChildPids(self, pid):
    raise NotImplementedError()

  def GetCommandLine(self, pid):
    raise NotImplementedError()

  def GetDeviceTypeName(self):
    raise NotImplementedError()

  def GetArchName(self):
    raise NotImplementedError()

  def GetOSName(self):
    raise NotImplementedError()

  def GetOSVersionName(self):
    raise NotImplementedError()

  def CanFlushIndividualFilesFromSystemCache(self):
    raise NotImplementedError()

  def SupportFlushEntireSystemCache(self):
    return False

  def FlushEntireSystemCache(self):
    raise NotImplementedError()

  def FlushSystemCacheForDirectory(self, directory):
    raise NotImplementedError()

  def FlushDnsCache(self):
    pass

  def LaunchApplication(
      self, application, parameters=None, elevate_privilege=False):
    raise NotImplementedError()

  def IsApplicationRunning(self, application):
    raise NotImplementedError()

  def CanLaunchApplication(self, application):
    return False

  def InstallApplication(self, application):
    raise NotImplementedError()

  def CanCaptureVideo(self):
    return False

  def StartVideoCapture(self, min_bitrate_mbps):
    raise NotImplementedError()

  @property
  def is_video_capture_running(self):
    return False

  def StopVideoCapture(self):
    raise NotImplementedError()

  def CanMonitorPower(self):
    return False

  def CanMeasurePerApplicationPower(self):
    return False

  def StartMonitoringPower(self, browser):
    raise NotImplementedError()

  def StopMonitoringPower(self):
    raise NotImplementedError()

  def CanMonitorNetworkData(self):
    return False

  def GetNetworkData(self, browser):
    raise NotImplementedError()

  def ReadMsr(self, msr_number, start=0, length=64):
    """Read a CPU model-specific register (MSR).

    Which MSRs are available depends on the CPU model.
    On systems with multiple CPUs, this function may run on any CPU.

    Args:
      msr_number: The number of the register to read.
      start: The least significant bit to read, zero-indexed.
          (Said another way, the number of bits to right-shift the MSR value.)
      length: The number of bits to read. MSRs are 64 bits, even on 32-bit CPUs.
    """
    raise NotImplementedError()

  @property
  def supports_test_ca(self):
    """Indicates whether the platform supports installing test CA."""
    return False

  def InstallTestCa(self, ca_cert_path):
    """Install a test CA on the platform."""
    raise NotImplementedError()

  def RemoveTestCa(self):
    """Remove a previously installed test CA from the platform."""
    raise NotImplementedError()

  def CanTakeScreenshot(self):
    return False

  def TakeScreenshot(self, file_path):
    raise NotImplementedError

  def IsCooperativeShutdownSupported(self):
    """Indicates whether CooperativelyShutdown, below, is supported.
    It is not necessary to implement it on all platforms."""
    return False

  def CooperativelyShutdown(self, proc, app_name):
    """Cooperatively shut down the given process from subprocess.Popen.

    Currently this is only implemented on Windows. See
    crbug.com/424024 for background on why it was added.

    Args:
      proc: a process object returned from subprocess.Popen.
      app_name: on Windows, is the prefix of the application's window
          class name that should be searched for. This helps ensure
          that only the application's windows are closed.

    Returns True if it is believed the attempt succeeded.
    """
    raise NotImplementedError()

  def PathExists(self, path, timeout=None, retries=None):
    """Tests whether the given path exists on the target platform.
    Args:
      path: path in request.
      timeout: timeout.
      retries: num of retries.
    Return:
      Whether the path exists on the target platform.
    """
    raise NotImplementedError()

  def HasBattOrConnected(self):
    return battor_wrapper.IsBattOrConnected(self.GetOSName())

  def WaitForTemperature(self, temp):
    """Waits for device under test to cool down to temperature given.
    Args:
      temp: temperature target in degrees C.
    """
    pass
