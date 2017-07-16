# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A server that serves MSR values over TCP. Takes a port as its sole parameter.

The reference client for this server is msr_power_monitor.MsrPowerMonitor.

Must be run as Administrator. We use TCP instead of named pipes or another IPC
to avoid dealing with the pipe security mechanisms. We take the port as a
parameter instead of choosing one, because it's hard to communicate the port
number across integrity levels.

Requires WinRing0 to be installed in the Python directory.
msr_power_monitor.MsrPowerMonitor does this if needed.
"""

import argparse
import ctypes
import os
import SocketServer
import struct
import sys
try:
  import win32api  # pylint: disable=import-error
  import win32file  # pylint: disable=import-error
except ImportError:
  win32api = None
  win32file = None


WINRING0_STATUS_MESSAGES = (
    'No error',
    'Unsupported platform',
    'Driver not loaded. You may need to run as Administrator',
    'Driver not found',
    'Driver unloaded by other process',
    'Driver not loaded because of executing on Network Drive',
    'Unknown error',
)


# The DLL initialization is global, so put it in a global variable.
_winring0 = None


class WinRing0Error(OSError):
  pass


def _WinRing0Path():
  python_is_64_bit = sys.maxsize > 2 ** 32
  dll_file_name = 'WinRing0x64.dll' if python_is_64_bit else 'WinRing0.dll'
  return os.path.join(os.path.dirname(sys.executable), dll_file_name)


def _Initialize():
  global _winring0
  if not _winring0:
    winring0 = ctypes.WinDLL(_WinRing0Path())
    if not winring0.InitializeOls():
      winring0_status = winring0.GetDllStatus()
      raise WinRing0Error(winring0_status,
                          'Unable to initialize WinRing0: %s' %
                          WINRING0_STATUS_MESSAGES[winring0_status])
    _winring0 = winring0


def _Deinitialize():
  global _winring0
  if _winring0:
    _winring0.DeinitializeOls()
    _winring0 = None


def _ReadMsr(msr_number):
  low = ctypes.c_uint()
  high = ctypes.c_uint()
  _winring0.Rdmsr(ctypes.c_uint(msr_number),
                  ctypes.byref(low), ctypes.byref(high))
  return high.value << 32 | low.value


class MsrRequestHandler(SocketServer.StreamRequestHandler):
  def handle(self):
    msr_number = struct.unpack('I', self.rfile.read(4))[0]
    self.wfile.write(struct.pack('Q', _ReadMsr(msr_number)))


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('pipe_name', type=str)
  args = parser.parse_args()

  _Initialize()
  try:
    SocketServer.TCPServer.allow_reuse_address = True
    server_address = ('127.0.0.1', 0)
    server = SocketServer.TCPServer(server_address, MsrRequestHandler)
    handle = win32file.CreateFile(args.pipe_name,
                                  win32file.GENERIC_WRITE,
                                  0, None,
                                  win32file.OPEN_EXISTING,
                                  0, None)
    _, port = server.server_address
    win32file.WriteFile(handle, str(port))
    win32api.CloseHandle(handle)
    server.serve_forever()
  finally:
    _Deinitialize()


if __name__ == '__main__':
  main()
