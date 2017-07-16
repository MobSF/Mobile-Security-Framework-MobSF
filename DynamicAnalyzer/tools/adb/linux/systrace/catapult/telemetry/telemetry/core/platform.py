# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging as real_logging
import os
import sys

from telemetry.core import discover
from telemetry.core import local_server
from telemetry.core import memory_cache_http_server
from telemetry.core import network_controller
from telemetry.core import tracing_controller
from telemetry.core import util
from telemetry.internal.platform import (platform_backend as
                                         platform_backend_module)

_host_platform = None
# Remote platform is a dictionary from device ids to remote platform instances.
_remote_platforms = {}


def _InitHostPlatformIfNeeded():
  global _host_platform
  if _host_platform:
    return
  backend = None
  backends = _IterAllPlatformBackendClasses()
  for platform_backend_class in backends:
    if platform_backend_class.IsPlatformBackendForHost():
      backend = platform_backend_class()
      break
  if not backend:
    raise NotImplementedError()
  _host_platform = Platform(backend)


def GetHostPlatform():
  _InitHostPlatformIfNeeded()
  return _host_platform


def _IterAllPlatformBackendClasses():
  platform_dir = os.path.dirname(os.path.realpath(
      platform_backend_module.__file__))
  return discover.DiscoverClasses(
      platform_dir, util.GetTelemetryDir(),
      platform_backend_module.PlatformBackend).itervalues()


def GetPlatformForDevice(device, finder_options, logging=real_logging):
  """ Returns a platform instance for the device.
    Args:
      device: a device.Device instance.
  """
  if device.guid in _remote_platforms:
    return _remote_platforms[device.guid]
  try:
    for platform_backend_class in _IterAllPlatformBackendClasses():
      if platform_backend_class.SupportsDevice(device):
        _remote_platforms[device.guid] = (
            platform_backend_class.CreatePlatformForDevice(device,
                                                           finder_options))
        return _remote_platforms[device.guid]
    return None
  except Exception:
    current_exception = sys.exc_info()
    logging.error('Fail to create platform instance for %s.', device.name)
    raise current_exception[0], current_exception[1], current_exception[2]


class Platform(object):
  """The platform that the target browser is running on.

  Provides a limited interface to interact with the platform itself, where
  possible. It's important to note that platforms may not provide a specific
  API, so check with IsFooBar() for availability.
  """

  def __init__(self, platform_backend):
    self._platform_backend = platform_backend
    self._platform_backend.InitPlatformBackend()
    self._platform_backend.SetPlatform(self)
    self._network_controller = network_controller.NetworkController(
        self._platform_backend.network_controller_backend)
    self._tracing_controller = tracing_controller.TracingController(
        self._platform_backend.tracing_controller_backend)
    self._local_server_controller = local_server.LocalServerController(
        self._platform_backend)
    self._is_monitoring_power = False

  @property
  def is_host_platform(self):
    return self == GetHostPlatform()

  @property
  def network_controller(self):
    """Control network settings and servers to simulate the Web."""
    return self._network_controller

  @property
  def tracing_controller(self):
    return self._tracing_controller

  def Initialize(self):
    pass

  def CanMonitorThermalThrottling(self):
    """Platforms may be able to detect thermal throttling.

    Some fan-less computers go into a reduced performance mode when their heat
    exceeds a certain threshold. Performance tests in particular should use this
    API to detect if this has happened and interpret results accordingly.
    """
    return self._platform_backend.CanMonitorThermalThrottling()

  def GetSystemLog(self):
    return self._platform_backend.GetSystemLog()

  def IsThermallyThrottled(self):
    """Returns True if the device is currently thermally throttled."""
    return self._platform_backend.IsThermallyThrottled()

  def HasBeenThermallyThrottled(self):
    """Returns True if the device has been thermally throttled."""
    return self._platform_backend.HasBeenThermallyThrottled()

  def GetDeviceTypeName(self):
    """Returns a string description of the Platform device, or None.

    Examples: Nexus 7, Nexus 6, Desktop"""
    return self._platform_backend.GetDeviceTypeName()

  def GetArchName(self):
    """Returns a string description of the Platform architecture.

    Examples: x86_64 (posix), AMD64 (win), armeabi-v7a, x86"""
    return self._platform_backend.GetArchName()

  def GetOSName(self):
    """Returns a string description of the Platform OS.

    Examples: WIN, MAC, LINUX, CHROMEOS"""
    return self._platform_backend.GetOSName()

  def GetOSVersionName(self):
    """Returns a logically sortable, string-like description of the Platform OS
    version.

    Examples: VISTA, WIN7, LION, MOUNTAINLION"""
    return self._platform_backend.GetOSVersionName()

  def GetOSVersionNumber(self):
    """Returns an integer description of the Platform OS major version.

    Examples: On Mac, 13 for Mavericks, 14 for Yosemite."""
    return self._platform_backend.GetOSVersionNumber()

  def GetSystemTotalPhysicalMemory(self):
    """Returns an integer with the total physical memory in bytes."""
    return self._platform_backend.GetSystemTotalPhysicalMemory()

  def CanFlushIndividualFilesFromSystemCache(self):
    """Returns true if the disk cache can be flushed for specific files."""
    return self._platform_backend.CanFlushIndividualFilesFromSystemCache()

  def SupportFlushEntireSystemCache(self):
    """Returns true if entire system cache can be flushed.

    Also checks that platform has required privilegues to flush system caches.
    """
    return self._platform_backend.SupportFlushEntireSystemCache()

  def FlushEntireSystemCache(self):
    """Flushes the OS's file cache completely.

    This function may require root or administrator access. Clients should
    call SupportFlushEntireSystemCache to check first.
    """
    return self._platform_backend.FlushEntireSystemCache()

  def FlushSystemCacheForDirectory(self, directory):
    """Flushes the OS's file cache for the specified directory.

    This function does not require root or administrator access."""
    return self._platform_backend.FlushSystemCacheForDirectory(directory)

  def FlushDnsCache(self):
    """Flushes the OS's DNS cache completely.

    This function may require root or administrator access."""
    return self._platform_backend.FlushDnsCache()

  def LaunchApplication(self,
                        application,
                        parameters=None,
                        elevate_privilege=False):
    """"Launches the given |application| with a list of |parameters| on the OS.

    Set |elevate_privilege| to launch the application with root or admin rights.

    Returns:
      A popen style process handle for host platforms.
    """
    return self._platform_backend.LaunchApplication(
        application,
        parameters,
        elevate_privilege=elevate_privilege)

  def IsApplicationRunning(self, application):
    """Returns whether an application is currently running."""
    return self._platform_backend.IsApplicationRunning(application)

  def CanLaunchApplication(self, application):
    """Returns whether the platform can launch the given application."""
    return self._platform_backend.CanLaunchApplication(application)

  def InstallApplication(self, application):
    """Installs the given application."""
    return self._platform_backend.InstallApplication(application)

  def CanCaptureVideo(self):
    """Returns a bool indicating whether the platform supports video capture."""
    return self._platform_backend.CanCaptureVideo()

  def StartVideoCapture(self, min_bitrate_mbps):
    """Starts capturing video.

    Outer framing may be included (from the OS, browser window, and webcam).

    Args:
      min_bitrate_mbps: The minimum capture bitrate in MegaBits Per Second.
          The platform is free to deliver a higher bitrate if it can do so
          without increasing overhead.

    Raises:
      ValueError if the required |min_bitrate_mbps| can't be achieved.
    """
    return self._platform_backend.StartVideoCapture(min_bitrate_mbps)

  def StopVideoCapture(self):
    """Stops capturing video.

    Returns:
      A telemetry.core.video.Video object.
    """
    return self._platform_backend.StopVideoCapture()

  def CanMonitorPower(self):
    """Returns True iff power can be monitored asynchronously via
    StartMonitoringPower() and StopMonitoringPower().
    """
    return self._platform_backend.CanMonitorPower()

  def CanMeasurePerApplicationPower(self):
    """Returns True if the power monitor can measure power for the target
    application in isolation. False if power measurement is for full system
    energy consumption."""
    return self._platform_backend.CanMeasurePerApplicationPower()

  def StartMonitoringPower(self, browser):
    """Starts monitoring power utilization statistics.

    Args:
      browser: The browser to monitor.
    """
    assert self._platform_backend.CanMonitorPower()
    self._platform_backend.StartMonitoringPower(browser)
    self._is_monitoring_power = True

  def StopMonitoringPower(self):
    """Stops monitoring power utilization and returns stats

    Returns:
      None if power measurement failed for some reason, otherwise a dict of
      power utilization statistics containing: {
        # An identifier for the data provider. Allows to evaluate the precision
        # of the data. Example values: monsoon, powermetrics, ds2784
        'identifier': identifier,

        # The instantaneous power (voltage * current) reading in milliwatts at
        # each sample.
        'power_samples_mw':  [mw0, mw1, ..., mwN],

        # The full system energy consumption during the sampling period in
        # milliwatt hours. May be estimated by integrating power samples or may
        # be exact on supported hardware.
        'energy_consumption_mwh': mwh,

        # The target application's energy consumption during the sampling period
        # in milliwatt hours. Should be returned iff
        # CanMeasurePerApplicationPower() return true.
        'application_energy_consumption_mwh': mwh,

        # A platform-specific dictionary of additional details about the
        # utilization of individual hardware components.
        component_utilization: {
          ...
        }
        # Platform-specific data not attributed to any particular hardware
        # component.
        platform_info: {

          # Device-specific onboard temperature sensor.
          'average_temperature_c': c,

           ...
        }

      }
    """
    ret_val = self._platform_backend.StopMonitoringPower()
    self._is_monitoring_power = False
    return ret_val

  def IsMonitoringPower(self):
    """Returns true if power is currently being monitored, false otherwise."""
    # TODO(rnephew): Remove when crbug.com/553601 is solved.
    real_logging.info('IsMonitoringPower: %s', self._is_monitoring_power)
    return self._is_monitoring_power

  def CanMonitorNetworkData(self):
    """Returns true if network data can be retrieved, false otherwise."""
    return self._platform_backend.CanMonitorNetworkData()

  def GetNetworkData(self, browser):
    """Get current network data.
    Returns:
      Tuple of (sent_data, received_data) in kb if data can be found,
      None otherwise.
    """
    assert browser.platform == self
    return self._platform_backend.GetNetworkData(browser)

  def IsCooperativeShutdownSupported(self):
    """Indicates whether CooperativelyShutdown, below, is supported.
    It is not necessary to implement it on all platforms."""
    return self._platform_backend.IsCooperativeShutdownSupported()

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
    return self._platform_backend.CooperativelyShutdown(proc, app_name)

  def CanTakeScreenshot(self):
    return self._platform_backend.CanTakeScreenshot()

  # TODO(nednguyen): Implement this on Mac, Linux & Win. (crbug.com/369490)
  def TakeScreenshot(self, file_path):
    """ Takes a screenshot of the platform and save to |file_path|.

    Note that this method may not be supported on all platform, so check with
    CanTakeScreenshot before calling this.

    Args:
      file_path: Where to save the screenshot to. If the platform is remote,
        |file_path| is the path on the host platform.

    Returns True if it is believed the attempt succeeded.
    """
    return self._platform_backend.TakeScreenshot(file_path)

  def StartLocalServer(self, server):
    """Starts a LocalServer and associates it with this platform.
    |server.Close()| should be called manually to close the started server.
    """
    self._local_server_controller.StartServer(server)

  @property
  def http_server(self):
    return self._local_server_controller.GetRunningServer(
        memory_cache_http_server.MemoryCacheHTTPServer, None)

  def SetHTTPServerDirectories(self, paths):
    """Returns True if the HTTP server was started, False otherwise."""
    if isinstance(paths, basestring):
      paths = set([paths])
    paths = set(os.path.realpath(p) for p in paths)

    # If any path is in a subdirectory of another, remove the subdirectory.
    duplicates = set()
    for parent_path in paths:
      for sub_path in paths:
        if parent_path == sub_path:
          continue
        if os.path.commonprefix((parent_path, sub_path)) == parent_path:
          duplicates.add(sub_path)
    paths -= duplicates

    if self.http_server:
      if paths and self.http_server.paths == paths:
        return False

      self.http_server.Close()

    if not paths:
      return False

    server = memory_cache_http_server.MemoryCacheHTTPServer(paths)
    self.StartLocalServer(server)
    return True

  def StopAllLocalServers(self):
    self._local_server_controller.Close()

  @property
  def local_servers(self):
    """Returns the currently running local servers."""
    return self._local_server_controller.local_servers

  def HasBattOrConnected(self):
    return  self._platform_backend.HasBattOrConnected()

  def WaitForTemperature(self, temp):
    return self._platform_backend.WaitForTemperature(temp)
