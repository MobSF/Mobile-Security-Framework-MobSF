# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import ctypes
import ctypes.util
import logging
import os
import platform
import sys
import time
import threading


GET_TICK_COUNT_LAST_NOW = 0
# If GET_TICK_COUNTER_LAST_NOW is less than the current time, the clock has
# rolled over, and this needs to be accounted for.
GET_TICK_COUNT_WRAPAROUNDS = 0
# The current detected platform
_CLOCK = None
_NOW_FUNCTION = None
# Mapping of supported platforms and what is returned by sys.platform.
_PLATFORMS = {
    'mac': 'darwin',
    'linux': 'linux',
    'windows': 'win32',
    'cygwin': 'cygwin',
    'freebsd': 'freebsd',
    'sunos': 'sunos5',
    'bsd': 'bsd'
}
# Mapping of what to pass get_clocktime based on platform.
_CLOCK_MONOTONIC = {
    'linux': 1,
    'freebsd': 4,
    'bsd': 3,
    'sunos5': 4
}

_LINUX_CLOCK = 'LINUX_CLOCK_MONOTONIC'
_MAC_CLOCK = 'MAC_MACH_ABSOLUTE_TIME'
_WIN_HIRES = 'WIN_QPC'
_WIN_LORES = 'WIN_ROLLOVER_PROTECTED_TIME_GET_TIME'

def InitializeMacNowFunction(plat):
  """Sets a monotonic clock for the Mac platform.

    Args:
      plat: Platform that is being run on. Unused in GetMacNowFunction. Passed
        for consistency between initilaizers.
  """
  del plat  # Unused
  global _CLOCK  # pylint: disable=global-statement
  global _NOW_FUNCTION  # pylint: disable=global-statement
  _CLOCK = _MAC_CLOCK
  libc = ctypes.CDLL('/usr/lib/libc.dylib', use_errno=True)
  class MachTimebaseInfoData(ctypes.Structure):
    """System timebase info. Defined in <mach/mach_time.h>."""
    _fields_ = (('numer', ctypes.c_uint32),
                ('denom', ctypes.c_uint32))

  mach_absolute_time = libc.mach_absolute_time
  mach_absolute_time.restype = ctypes.c_uint64

  timebase = MachTimebaseInfoData()
  libc.mach_timebase_info(ctypes.byref(timebase))
  ticks_per_second = timebase.numer / timebase.denom * 1.0e9

  def MacNowFunctionImpl():
    return mach_absolute_time() / ticks_per_second
  _NOW_FUNCTION = MacNowFunctionImpl


def GetClockGetTimeClockNumber(plat):
  for key in _CLOCK_MONOTONIC:
    if plat.startswith(key):
      return _CLOCK_MONOTONIC[key]
  raise LookupError('Platform not in clock dicitonary')

def InitializeLinuxNowFunction(plat):
  """Sets a monotonic clock for linux platforms.

    Args:
      plat: Platform that is being run on.
  """
  global _CLOCK  # pylint: disable=global-statement
  global _NOW_FUNCTION  # pylint: disable=global-statement
  _CLOCK = _LINUX_CLOCK
  clock_monotonic = GetClockGetTimeClockNumber(plat)
  try:
    # Attempt to find clock_gettime in the C library.
    clock_gettime = ctypes.CDLL(ctypes.util.find_library('c'),
                                use_errno=True).clock_gettime
  except AttributeError:
    # If not able to find int in the C library, look in rt library.
    clock_gettime = ctypes.CDLL(ctypes.util.find_library('rt'),
                                use_errno=True).clock_gettime

  class Timespec(ctypes.Structure):
    """Time specification, as described in clock_gettime(3)."""
    _fields_ = (('tv_sec', ctypes.c_long),
                ('tv_nsec', ctypes.c_long))

  def LinuxNowFunctionImpl():
    ts = Timespec()
    if clock_gettime(clock_monotonic, ctypes.pointer(ts)):
      errno = ctypes.get_errno()
      raise OSError(errno, os.strerror(errno))
    return ts.tv_sec + ts.tv_nsec / 1.0e9

  _NOW_FUNCTION = LinuxNowFunctionImpl


def IsQPCUsable():
  """Determines if system can query the performance counter.
    The performance counter is a high resolution timer on windows systems.
    Some chipsets have unreliable performance counters, so this checks that one
    of those chipsets is not present.

    Returns:
      True if QPC is useable, false otherwise.
  """

  # Sample output: 'Intel64 Family 6 Model 23 Stepping 6, GenuineIntel'
  info = platform.processor()
  if 'AuthenticAMD' in info and 'Family 15' in info:
    return False
  try:  # If anything goes wrong during this, assume QPC isn't available.
    frequency = ctypes.c_int64()
    ctypes.windll.Kernel32.QueryPerformanceFrequency(
        ctypes.byref(frequency))
    if float(frequency.value) <= 0:
      return False
  except Exception:  # pylint: disable=broad-except
    logging.exception('Error when determining if QPC is usable.')
    return False
  return True


def InitializeWinNowFunction(plat):
  """Sets a monotonic clock for windows platforms.

    Args:
      plat: Platform that is being run on.
  """
  global _CLOCK  # pylint: disable=global-statement
  global _NOW_FUNCTION  # pylint: disable=global-statement

  if IsQPCUsable():
    _CLOCK = _WIN_HIRES
    qpc_return = ctypes.c_int64()
    qpc_frequency = ctypes.c_int64()
    ctypes.windll.Kernel32.QueryPerformanceFrequency(
        ctypes.byref(qpc_frequency))
    qpc_frequency = float(qpc_frequency.value)
    qpc = ctypes.windll.Kernel32.QueryPerformanceCounter

    def WinNowFunctionImpl():
      qpc(ctypes.byref(qpc_return))
      return qpc_return.value / qpc_frequency

  else:
    _CLOCK = _WIN_LORES
    kernel32 = (ctypes.cdll.kernel32
                if plat.startswith(_PLATFORMS['cygwin'])
                else ctypes.windll.kernel32)
    get_tick_count_64 = getattr(kernel32, 'GetTickCount64', None)

    # Windows Vista or newer
    if get_tick_count_64:
      get_tick_count_64.restype = ctypes.c_ulonglong

      def WinNowFunctionImpl():
        return get_tick_count_64() / 1000.0

    else:  # Pre Vista.
      get_tick_count = kernel32.GetTickCount
      get_tick_count.restype = ctypes.c_uint32
      get_tick_count_lock = threading.Lock()

      def WinNowFunctionImpl():
        global GET_TICK_COUNT_LAST_NOW  # pylint: disable=global-statement
        global GET_TICK_COUNT_WRAPAROUNDS  # pylint: disable=global-statement
        with get_tick_count_lock:
          current_sample = get_tick_count()
          if current_sample < GET_TICK_COUNT_LAST_NOW:
            GET_TICK_COUNT_WRAPAROUNDS += 1
          GET_TICK_COUNT_LAST_NOW = current_sample
          final_ms = GET_TICK_COUNT_WRAPAROUNDS << 32
          final_ms += GET_TICK_COUNT_LAST_NOW
          return final_ms / 1000.0

  _NOW_FUNCTION = WinNowFunctionImpl


def InitializeNowFunction(plat):
  """Sets a monotonic clock for the current platform.

    Args:
      plat: Platform that is being run on.
  """
  if plat.startswith(_PLATFORMS['mac']):
    InitializeMacNowFunction(plat)

  elif (plat.startswith(_PLATFORMS['linux'])
        or plat.startswith(_PLATFORMS['freebsd'])
        or plat.startswith(_PLATFORMS['bsd'])
        or plat.startswith(_PLATFORMS['sunos'])):
    InitializeLinuxNowFunction(plat)

  elif (plat.startswith(_PLATFORMS['windows'])
        or plat.startswith(_PLATFORMS['cygwin'])):
    InitializeWinNowFunction(plat)

  else:
    raise RuntimeError('%s is not a supported platform.' % plat)

  global _NOW_FUNCTION
  global _CLOCK
  assert _NOW_FUNCTION, 'Now function not properly set during initialization.'
  assert _CLOCK, 'Clock not properly set during initialization.'


def Now():
  return _NOW_FUNCTION() * 1e6  # convert from seconds to microseconds


def GetClock():
  return _CLOCK


InitializeNowFunction(sys.platform)
