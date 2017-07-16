# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import posixpath
import re
import subprocess
import tempfile

from battor import battor_wrapper
from telemetry.core import android_platform
from telemetry.core import exceptions
from telemetry.core import util
from telemetry import decorators
from telemetry.internal import forwarders
from telemetry.internal.forwarders import android_forwarder
from telemetry.internal.image_processing import video
from telemetry.internal.platform import android_device
from telemetry.internal.platform import linux_based_platform_backend
from telemetry.internal.platform.power_monitor import android_dumpsys_power_monitor
from telemetry.internal.platform.power_monitor import android_fuelgauge_power_monitor
from telemetry.internal.platform.power_monitor import android_temperature_monitor
from telemetry.internal.platform.power_monitor import monsoon_power_monitor
from telemetry.internal.platform.power_monitor import (
  android_power_monitor_controller)
from telemetry.internal.platform.power_monitor import sysfs_power_monitor
from telemetry.internal.platform.profiler import android_prebuilt_profiler_helper
from telemetry.internal.util import binary_manager
from telemetry.internal.util import external_modules

psutil = external_modules.ImportOptionalModule('psutil')
import adb_install_cert

from devil.android import app_ui
from devil.android import battery_utils
from devil.android import device_errors
from devil.android import device_utils
from devil.android.perf import cache_control
from devil.android.perf import perf_control
from devil.android.perf import thermal_throttle
from devil.android.sdk import version_codes
from devil.android.tools import video_recorder

try:
  # devil.android.forwarder uses fcntl, which doesn't exist on Windows.
  from devil.android import forwarder
except ImportError:
  forwarder = None

try:
  from devil.android.perf import surface_stats_collector
except Exception:
  surface_stats_collector = None


_ARCH_TO_STACK_TOOL_ARCH = {
  'armeabi-v7a': 'arm',
  'arm64-v8a': 'arm64',
}
_DEVICE_COPY_SCRIPT_FILE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), 'efficient_android_directory_copy.sh'))
_DEVICE_COPY_SCRIPT_LOCATION = (
    '/data/local/tmp/efficient_android_directory_copy.sh')

# TODO(nednguyen): Remove this method and update the client config to point to
# the correct binary instead.
def _FindLocallyBuiltPath(binary_name):
  """Finds the most recently built |binary_name|."""
  command = None
  command_mtime = 0
  required_mode = os.X_OK
  if binary_name.endswith('.apk'):
    required_mode = os.R_OK
  for build_path in util.GetBuildDirectories():
    candidate = os.path.join(build_path, binary_name)
    if os.path.isfile(candidate) and os.access(candidate, required_mode):
      candidate_mtime = os.stat(candidate).st_mtime
      if candidate_mtime > command_mtime:
        command = candidate
        command_mtime = candidate_mtime
  return command


class AndroidPlatformBackend(
    linux_based_platform_backend.LinuxBasedPlatformBackend):
  def __init__(self, device):
    assert device, (
        'AndroidPlatformBackend can only be initialized from remote device')
    super(AndroidPlatformBackend, self).__init__(device)
    self._device = device_utils.DeviceUtils(device.device_id)
    # Trying to root the device, if possible.
    if not self._device.HasRoot():
      try:
        self._device.EnableRoot()
      except device_errors.CommandFailedError:
        logging.warning('Unable to root %s', str(self._device))
    self._battery = battery_utils.BatteryUtils(self._device)
    self._enable_performance_mode = device.enable_performance_mode
    self._surface_stats_collector = None
    self._perf_tests_setup = perf_control.PerfControl(self._device)
    self._thermal_throttle = thermal_throttle.ThermalThrottle(self._device)
    self._raw_display_frame_rate_measurements = []
    self._can_elevate_privilege = (
        self._device.HasRoot() or self._device.NeedsSU())
    self._device_copy_script = None
    self._power_monitor = (
      android_power_monitor_controller.AndroidPowerMonitorController([
        android_temperature_monitor.AndroidTemperatureMonitor(self._device),
        monsoon_power_monitor.MonsoonPowerMonitor(self._device, self),
        android_dumpsys_power_monitor.DumpsysPowerMonitor(
          self._battery, self),
        sysfs_power_monitor.SysfsPowerMonitor(self, standalone=True),
        android_fuelgauge_power_monitor.FuelGaugePowerMonitor(
            self._battery),
    ], self._battery))
    self._video_recorder = None
    self._installed_applications = None

    self._device_cert_util = None
    self._system_ui = None

    _FixPossibleAdbInstability()

  @property
  def log_file_path(self):
    return None

  @classmethod
  def SupportsDevice(cls, device):
    return isinstance(device, android_device.AndroidDevice)

  @classmethod
  def CreatePlatformForDevice(cls, device, finder_options):
    assert cls.SupportsDevice(device)
    platform_backend = AndroidPlatformBackend(device)
    return android_platform.AndroidPlatform(platform_backend)

  @property
  def forwarder_factory(self):
    if not self._forwarder_factory:
      self._forwarder_factory = android_forwarder.AndroidForwarderFactory(
          self._device)

    return self._forwarder_factory

  @property
  def device(self):
    return self._device

  def Initialize(self):
    self.EnsureBackgroundApkInstalled()

  def GetSystemUi(self):
    if self._system_ui is None:
      self._system_ui = app_ui.AppUi(self.device, 'com.android.systemui')
    return self._system_ui

  def IsSvelte(self):
    description = self._device.GetProp('ro.build.description', cache=True)
    if description is not None:
      return 'svelte' in description
    else:
      return False

  def GetRemotePort(self, port):
    return forwarder.Forwarder.DevicePortForHostPort(port) or 0

  def IsDisplayTracingSupported(self):
    return bool(self.GetOSVersionName() >= 'J')

  def StartDisplayTracing(self):
    assert not self._surface_stats_collector
    # Clear any leftover data from previous timed out tests
    self._raw_display_frame_rate_measurements = []
    self._surface_stats_collector = \
        surface_stats_collector.SurfaceStatsCollector(self._device)
    self._surface_stats_collector.Start()

  def StopDisplayTracing(self):
    if not self._surface_stats_collector:
      return

    try:
      refresh_period, timestamps = self._surface_stats_collector.Stop()
      pid = self._surface_stats_collector.GetSurfaceFlingerPid()
    finally:
      self._surface_stats_collector = None
    # TODO(sullivan): should this code be inline, or live elsewhere?
    events = []
    for ts in timestamps:
      events.append({
        'cat': 'SurfaceFlinger',
        'name': 'vsync_before',
        'ts': ts,
        'pid': pid,
        'tid': pid,
        'args': {'data': {
          'frame_count': 1,
          'refresh_period': refresh_period,
        }}
      })
    return events

  def CanTakeScreenshot(self):
    return True

  def TakeScreenshot(self, file_path):
    return bool(self._device.TakeScreenshot(host_path=file_path))

  def SetFullPerformanceModeEnabled(self, enabled):
    if not self._enable_performance_mode:
      logging.warning('CPU governor will not be set!')
      return
    if enabled:
      self._perf_tests_setup.SetHighPerfMode()
    else:
      self._perf_tests_setup.SetDefaultPerfMode()

  def CanMonitorThermalThrottling(self):
    return True

  def IsThermallyThrottled(self):
    return self._thermal_throttle.IsThrottled()

  def HasBeenThermallyThrottled(self):
    return self._thermal_throttle.HasBeenThrottled()

  def GetCpuStats(self, pid):
    if not self._can_elevate_privilege:
      logging.warning('CPU stats cannot be retrieved on non-rooted device.')
      return {}
    return super(AndroidPlatformBackend, self).GetCpuStats(pid)

  def GetCpuTimestamp(self):
    if not self._can_elevate_privilege:
      logging.warning('CPU timestamp cannot be retrieved on non-rooted device.')
      return {}
    return super(AndroidPlatformBackend, self).GetCpuTimestamp()

  def SetGraphicsMemoryTrackingEnabled(self, enabled):
    if not enabled:
      self.KillApplication('memtrack_helper')
      return

    if not android_prebuilt_profiler_helper.InstallOnDevice(
        self._device, 'memtrack_helper'):
      raise Exception('Error installing memtrack_helper.')
    self._device.RunShellCommand([
      android_prebuilt_profiler_helper.GetDevicePath('memtrack_helper'),
      '-d'], as_root=True, check_return=True)

  def EnsureBackgroundApkInstalled(self):
    app = 'push_apps_to_background_apk'
    arch_name = self._device.GetABI()
    host_path = binary_manager.FetchPath(app, arch_name, 'android')
    if not host_path:
      raise Exception('Error installing PushAppsToBackground.apk.')
    self.InstallApplication(host_path)

  def PurgeUnpinnedMemory(self):
    """Purges the unpinned ashmem memory for the whole system.

    This can be used to make memory measurements more stable. Requires root.
    """
    if not self._can_elevate_privilege:
      logging.warning('Cannot run purge_ashmem. Requires a rooted device.')
      return

    if not android_prebuilt_profiler_helper.InstallOnDevice(
        self._device, 'purge_ashmem'):
      raise Exception('Error installing purge_ashmem.')
    output = self._device.RunShellCommand([
      android_prebuilt_profiler_helper.GetDevicePath('purge_ashmem')],
      check_return=True)
    for l in output:
      logging.info(l)

  @decorators.Deprecated(
      2017, 11, 4,
      'Clients should use tracing and memory-infra in new Telemetry '
      'benchmarks. See for context: https://crbug.com/632021')
  def GetMemoryStats(self, pid):
    memory_usage = self._device.GetMemoryUsageForPid(pid)
    if not memory_usage:
      return {}
    return {'ProportionalSetSize': memory_usage['Pss'] * 1024,
            'SharedDirty': memory_usage['Shared_Dirty'] * 1024,
            'PrivateDirty': memory_usage['Private_Dirty'] * 1024,
            'VMPeak': memory_usage['VmHWM'] * 1024}

  def GetChildPids(self, pid):
    child_pids = []
    ps = self.GetPsOutput(['pid', 'name'])
    for curr_pid, curr_name in ps:
      if int(curr_pid) == pid:
        name = curr_name
        for curr_pid, curr_name in ps:
          if curr_name.startswith(name) and curr_name != name:
            child_pids.append(int(curr_pid))
        break
    return child_pids

  @decorators.Cache
  def GetCommandLine(self, pid):
    ps = self.GetPsOutput(['pid', 'name'], pid)
    if not ps:
      raise exceptions.ProcessGoneException()
    return ps[0][1]

  @decorators.Cache
  def GetArchName(self):
    return self._device.GetABI()

  def GetOSName(self):
    return 'android'

  def GetDeviceTypeName(self):
    return self._device.product_model

  @decorators.Cache
  def GetOSVersionName(self):
    return self._device.GetProp('ro.build.id')[0]

  def CanFlushIndividualFilesFromSystemCache(self):
    return False

  def SupportFlushEntireSystemCache(self):
    return self._can_elevate_privilege

  def FlushEntireSystemCache(self):
    cache = cache_control.CacheControl(self._device)
    cache.DropRamCaches()

  def FlushSystemCacheForDirectory(self, directory):
    raise NotImplementedError()

  def FlushDnsCache(self):
    self._device.RunShellCommand(
        ['ndc', 'resolver', 'flushdefaultif'], as_root=True, check_return=True)

  def StopApplication(self, application):
    """Stop the given |application|.

    Args:
       application: The full package name string of the application to stop.
    """
    self._device.ForceStop(application)

  def KillApplication(self, application):
    """Kill the given |application|.

    Might be used instead of ForceStop for efficiency reasons.

    Args:
      application: The full package name string of the application to kill.
    """
    assert isinstance(application, basestring)
    self._device.KillAll(application, blocking=True, quiet=True)

  def LaunchApplication(
      self, application, parameters=None, elevate_privilege=False):
    """Launches the given |application| with a list of |parameters| on the OS.

    Args:
      application: The full package name string of the application to launch.
      parameters: A list of parameters to be passed to the ActivityManager.
      elevate_privilege: Currently unimplemented on Android.
    """
    if elevate_privilege:
      raise NotImplementedError("elevate_privilege isn't supported on android.")
    # TODO(catapult:#3215): Migrate to StartActivity.
    cmd = ['am', 'start']
    if parameters:
      cmd.extend(parameters)
    cmd.append(application)
    result_lines = self._device.RunShellCommand(cmd, check_return=True)
    for line in result_lines:
      if line.startswith('Error: '):
        raise ValueError('Failed to start "%s" with error\n  %s' %
                         (application, line))

  def IsApplicationRunning(self, application):
    return len(self._device.GetPids(application)) > 0

  def CanLaunchApplication(self, application):
    if not self._installed_applications:
      self._installed_applications = self._device.RunShellCommand(
          ['pm', 'list', 'packages'], check_return=True)
    return 'package:' + application in self._installed_applications

  def InstallApplication(self, application):
    self._installed_applications = None
    self._device.Install(application)

  @decorators.Cache
  def CanCaptureVideo(self):
    return self.GetOSVersionName() >= 'K'

  def StartVideoCapture(self, min_bitrate_mbps):
    """Starts the video capture at specified bitrate."""
    min_bitrate_mbps = max(min_bitrate_mbps, 0.1)
    if min_bitrate_mbps > 100:
      raise ValueError('Android video capture cannot capture at %dmbps. '
                       'Max capture rate is 100mbps.' % min_bitrate_mbps)
    if self.is_video_capture_running:
      self._video_recorder.Stop()
    self._video_recorder = video_recorder.VideoRecorder(
        self._device, megabits_per_second=min_bitrate_mbps)
    self._video_recorder.Start(timeout=5)

  @property
  def is_video_capture_running(self):
    return self._video_recorder is not None

  def StopVideoCapture(self):
    assert self.is_video_capture_running, 'Must start video capture first'
    self._video_recorder.Stop()
    video_file_obj = tempfile.NamedTemporaryFile()
    self._video_recorder.Pull(video_file_obj.name)
    self._video_recorder = None

    return video.Video(video_file_obj)

  def CanMonitorPower(self):
    return self._power_monitor.CanMonitorPower()

  def StartMonitoringPower(self, browser):
    self._power_monitor.StartMonitoringPower(browser)

  def StopMonitoringPower(self):
    return self._power_monitor.StopMonitoringPower()

  def CanMonitorNetworkData(self):
    return self._device.build_version_sdk >= version_codes.LOLLIPOP

  def GetNetworkData(self, browser):
    return self._battery.GetNetworkData(browser._browser_backend.package)

  def PathExists(self, device_path, timeout=None, retries=None):
    """ Return whether the given path exists on the device.
    This method is the same as
    devil.android.device_utils.DeviceUtils.PathExists.
    """
    return self._device.PathExists(
        device_path, timeout=timeout, retries=retries)

  def GetFileContents(self, fname):
    if not self._can_elevate_privilege:
      logging.warning('%s cannot be retrieved on non-rooted device.', fname)
      return ''
    return self._device.ReadFile(fname, as_root=True)

  def GetPsOutput(self, columns, pid=None):
    assert columns == ['pid', 'name'] or columns == ['pid'], \
        'Only know how to return pid and name. Requested: ' + columns
    if pid is not None:
      pid = str(pid)
    procs_pids = self._device.GetPids()
    output = []
    for curr_name, pids_list in procs_pids.iteritems():
      for curr_pid in pids_list:
        if columns == ['pid', 'name']:
          row = [curr_pid, curr_name]
        else:
          row = [curr_pid]
        if pid is not None:
          if curr_pid == pid:
            return [row]
        else:
          output.append(row)
    return output

  def RunCommand(self, command):
    return '\n'.join(self._device.RunShellCommand(command, check_return=True))

  @staticmethod
  def ParseCStateSample(sample):
    sample_stats = {}
    for cpu in sample:
      values = sample[cpu].splitlines()
      # Each state has three values after excluding the time value.
      num_states = (len(values) - 1) / 3
      names = values[:num_states]
      times = values[num_states:2 * num_states]
      cstates = {'C0': int(values[-1]) * 10 ** 6}
      for i, state in enumerate(names):
        if state == 'C0':
          # The Exynos cpuidle driver for the Nexus 10 uses the name 'C0' for
          # its WFI state.
          # TODO(tmandel): We should verify that no other Android device
          # actually reports time in C0 causing this to report active time as
          # idle time.
          state = 'WFI'
        cstates[state] = int(times[i])
        cstates['C0'] -= int(times[i])
      sample_stats[cpu] = cstates
    return sample_stats

  def SetRelaxSslCheck(self, value):
    old_flag = self._device.GetProp('socket.relaxsslcheck')
    self._device.SetProp('socket.relaxsslcheck', value)
    return old_flag

  def ForwardHostToDevice(self, host_port, device_port):
    self._device.adb.Forward('tcp:%d' % host_port, device_port)

  def StopForwardingHost(self, host_port):
    # This used to run `adb forward --list` to check that the requested
    # port was actually being forwarded to self._device. Unfortunately,
    # starting in adb 1.0.36, a bug (b/31811775) keeps this from working.
    # For now, try to remove the port forwarding and ignore failures.
    try:
      self._device.adb.ForwardRemove('tcp:%d' % host_port)
    except device_errors.AdbCommandFailedError:
      logging.critical(
          'Attempted to unforward port tcp:%d but failed.', host_port)

  def DismissCrashDialogIfNeeded(self):
    """Dismiss any error dialogs.

    Limit the number in case we have an error loop or we are failing to dismiss.
    """
    for _ in xrange(10):
      if not self._device.DismissCrashDialogIfNeeded():
        break

  def IsAppRunning(self, process_name):
    """Determine if the given process is running.

    Args:
      process_name: The full package name string of the process.
    """
    return bool(self._device.GetPids(process_name))

  @property
  def supports_test_ca(self):
    # TODO(nednguyen): figure out how to install certificate on Android M
    # crbug.com/593152
    return self._device.build_version_sdk <= version_codes.LOLLIPOP_MR1

  def InstallTestCa(self, ca_cert_path):
    """Install a randomly generated root CA on the android device.

    This allows transparent HTTPS testing with WPR server without need
    to tweak application network stack.

    Note: If this method fails with any exception, then RemoveTestCa will be
    automatically called by the network_controller_backend.
    """
    if self._device_cert_util is not None:
      logging.warning('Test certificate authority is already installed.')
      return
    self._device_cert_util = adb_install_cert.AndroidCertInstaller(
        self._device.adb.GetDeviceSerial(), None, ca_cert_path,
        adb_path=self._device.adb.GetAdbPath())
    self._device_cert_util.install_cert(overwrite_cert=True)

  def RemoveTestCa(self):
    """Remove root CA from device installed by InstallTestCa.

    Note: Any exceptions raised by this method will be logged but dismissed by
    the network_controller_backend.
    """
    if self._device_cert_util is not None:
      try:
        self._device_cert_util.remove_cert()
      finally:
        self._device_cert_util = None

  def PushProfile(self, package, new_profile_dir):
    """Replace application profile with files found on host machine.

    Pushing the profile is slow, so we don't want to do it every time.
    Avoid this by pushing to a safe location using PushChangedFiles, and
    then copying into the correct location on each test run.

    Args:
      package: The full package name string of the application for which the
        profile is to be updated.
      new_profile_dir: Location where profile to be pushed is stored on the
        host machine.
    """
    (profile_parent, profile_base) = os.path.split(new_profile_dir)
    # If the path ends with a '/' python split will return an empty string for
    # the base name; so we now need to get the base name from the directory.
    if not profile_base:
      profile_base = os.path.basename(profile_parent)

    saved_profile_location = '/sdcard/profile/%s' % profile_base
    self._device.PushChangedFiles([(new_profile_dir, saved_profile_location)])

    profile_dir = self._GetProfileDir(package)
    self._EfficientDeviceDirectoryCopy(
        saved_profile_location, profile_dir)
    dumpsys = self._device.RunShellCommand(
        ['dumpsys', 'package', package], check_return=True)
    id_line = next(line for line in dumpsys if 'userId=' in line)
    uid = re.search(r'\d+', id_line).group()
    files = self._device.ListDirectory(profile_dir, as_root=True)
    paths = [posixpath.join(profile_dir, f) for f in files if f != 'lib']
    for path in paths:
      # TODO(crbug.com/628617): Implement without ignoring shell errors.
      # Note: need to pass command as a string for the shell to expand the *'s.
      extended_path = '%s %s/* %s/*/* %s/*/*/*' % (path, path, path, path)
      self._device.RunShellCommand(
          'chown %s.%s %s' % (uid, uid, extended_path),
          check_return=False, shell=True)

  def _EfficientDeviceDirectoryCopy(self, source, dest):
    if not self._device_copy_script:
      self._device.adb.Push(
          _DEVICE_COPY_SCRIPT_FILE,
          _DEVICE_COPY_SCRIPT_LOCATION)
      self._device_copy_script = _DEVICE_COPY_SCRIPT_LOCATION
    self._device.RunShellCommand(
        ['sh', self._device_copy_script, source, dest], check_return=True)

  def GetPortPairForForwarding(self, local_port):
    return forwarders.PortPair(local_port=local_port, remote_port=0)

  def RemoveProfile(self, package, ignore_list):
    """Delete application profile on device.

    Args:
      package: The full package name string of the application for which the
        profile is to be deleted.
      ignore_list: List of files to keep.
    """
    profile_dir = self._GetProfileDir(package)
    if not self._device.PathExists(profile_dir):
      return
    files = [
      posixpath.join(profile_dir, f)
      for f in self._device.ListDirectory(profile_dir, as_root=True)
      if f not in ignore_list]
    if not files:
      return
    self._device.RemovePath(files, recursive=True, as_root=True)

  def PullProfile(self, package, output_profile_path):
    """Copy application profile from device to host machine.

    Args:
      package: The full package name string of the application for which the
        profile is to be copied.
      output_profile_dir: Location where profile to be stored on host machine.
    """
    profile_dir = self._GetProfileDir(package)
    logging.info("Pulling profile directory from device: '%s'->'%s'.",
                 profile_dir, output_profile_path)
    # To minimize bandwidth it might be good to look at whether all the data
    # pulled down is really needed e.g. .pak files.
    if not os.path.exists(output_profile_path):
      os.makedirs(output_profile_path)
    problem_files = []
    for filename in self._device.ListDirectory(profile_dir, as_root=True):
      # Don't pull lib, since it is created by the installer.
      if filename == 'lib':
        continue
      source = posixpath.join(profile_dir, filename)
      dest = os.path.join(output_profile_path, filename)
      try:
        self._device.PullFile(source, dest, timeout=240)
      except device_errors.CommandFailedError:
        problem_files.append(source)
    if problem_files:
      # Some paths (e.g. 'files', 'app_textures') consistently fail to be
      # pulled from the device.
      logging.warning(
          'There were errors retrieving the following paths from the profile:')
      for filepath in problem_files:
        logging.warning('- %s', filepath)

  def _GetProfileDir(self, package):
    """Returns the on-device location where the application profile is stored
    based on Android convention.

    Args:
      package: The full package name string of the application.
    """
    return '/data/data/%s/' % package

  def SetDebugApp(self, package):
    """Set application to debugging.

    Args:
      package: The full package name string of the application.
    """
    if self._device.IsUserBuild():
      logging.debug('User build device, setting debug app')
      self._device.RunShellCommand(
          ['am', 'set-debug-app', '--persistent', package],
          check_return=True)

  def GetLogCat(self, number_of_lines=500):
    """Returns most recent lines of logcat dump.

    Args:
      number_of_lines: Number of lines of log to return.
    """
    def decode_line(line):
      try:
        uline = unicode(line, encoding='utf-8')
        return uline.encode('ascii', 'backslashreplace')
      except Exception:
        logging.error('Error encoding UTF-8 logcat line as ASCII.')
        return '<MISSING LOGCAT LINE: FAILED TO ENCODE>'

    logcat_output = self._device.RunShellCommand(
        ['logcat', '-d', '-t', str(number_of_lines)],
        check_return=True, large_output=True)
    return '\n'.join(decode_line(l) for l in logcat_output)

  def GetStandardOutput(self):
    return 'Cannot get standard output on Android'

  def GetStackTrace(self):
    """Returns stack trace.

    The stack trace consists of raw logcat dump, logcat dump with symbols,
    and stack info from tomstone files.
    """
    def Decorate(title, content):
      return "%s\n%s\n%s\n" % (title, content, '*' * 80)

    # Get the UI nodes that can be found on the screen
    ret = Decorate('UI dump', '\n'.join(self.GetSystemUi().ScreenDump()))

    # Get the last lines of logcat (large enough to contain stacktrace)
    logcat = self.GetLogCat()
    ret += Decorate('Logcat', logcat)
    stack = os.path.join(util.GetChromiumSrcDir(), 'third_party',
                         'android_platform', 'development', 'scripts', 'stack')
    # Try to symbolize logcat.
    if os.path.exists(stack):
      cmd = [stack]
      arch = self.GetArchName()
      arch = _ARCH_TO_STACK_TOOL_ARCH.get(arch, arch)
      cmd.append('--arch=%s' % arch)
      p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
      ret += Decorate('Stack from Logcat', p.communicate(input=logcat)[0])

    # Try to get tombstones.
    tombstones = os.path.join(util.GetChromiumSrcDir(), 'build', 'android',
                              'tombstones.py')
    if os.path.exists(tombstones):
      tombstones_cmd = [
          tombstones, '-w',
          '--device', self._device.adb.GetDeviceSerial(),
          '--adb-path', self._device.adb.GetAdbPath(),
      ]
      ret += Decorate('Tombstones',
                      subprocess.Popen(tombstones_cmd,
                                       stdout=subprocess.PIPE).communicate()[0])
    return (True, ret)

  def GetMinidumpPath(self):
    return None

  def IsScreenOn(self):
    """Determines if device screen is on."""
    return self._device.IsScreenOn()

  @staticmethod
  def _IsScreenLocked(input_methods):
    """Parser method for IsScreenLocked()

    Args:
      input_methods: Output from dumpsys input_methods

    Returns:
      boolean: True if screen is locked, false if screen is not locked.

    Raises:
      ValueError: An unknown value is found for the screen lock state.
      AndroidDeviceParsingError: Error in detecting screen state.

    """
    for line in input_methods:
      if 'mHasBeenInactive' in line:
        for pair in line.strip().split(' '):
          key, value = pair.split('=', 1)
          if key == 'mHasBeenInactive':
            if value == 'true':
              return True
            elif value == 'false':
              return False
            else:
              raise ValueError('Unknown value for %s: %s' % (key, value))
    raise exceptions.AndroidDeviceParsingError(str(input_methods))

  def IsScreenLocked(self):
    """Determines if device screen is locked."""
    input_methods = self._device.RunShellCommand(['dumpsys', 'input_method'],
                                                 check_return=True)
    return self._IsScreenLocked(input_methods)

  def HasBattOrConnected(self):
    # Use linux instead of Android because when determining what tests to run on
    # a bot the individual device could be down, which would make BattOr tests
    # not run on any device. BattOrs communicate with the host and not android
    # devices.
    return battor_wrapper.IsBattOrConnected('linux')

  def Log(self, message):
    """Prints line to logcat."""
    TELEMETRY_LOGCAT_TAG = 'Telemetry'
    self._device.RunShellCommand(
        ['log', '-p', 'i', '-t', TELEMETRY_LOGCAT_TAG, message],
        check_return=True)

  def WaitForTemperature(self, temp):
    # Temperature is in tenths of a degree C, so we convert to that scale.
    self._battery.LetBatteryCoolToTemperature(temp * 10)

def _FixPossibleAdbInstability():
  """Host side workaround for crbug.com/268450 (adb instability).

  The adb server has a race which is mitigated by binding to a single core.
  """
  if not psutil:
    return
  for process in psutil.process_iter():
    try:
      if psutil.version_info >= (2, 0):
        if 'adb' in process.name():
          process.cpu_affinity([0])
      else:
        if 'adb' in process.name:
          process.set_cpu_affinity([0])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
      logging.warn('Failed to set adb process CPU affinity')
