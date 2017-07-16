# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Hooks that apply globally to all scripts that import or use Telemetry."""
import signal
import sys

from telemetry.internal.util import exception_formatter


def InstallHooks():
  InstallUnhandledExceptionFormatter()
  InstallStackDumpOnSigusr1()
  InstallTerminationHook()

def InstallUnhandledExceptionFormatter():
  """Print prettier exceptions that also contain the stack frame's locals."""
  sys.excepthook = exception_formatter.PrintFormattedException


def InstallStackDumpOnSigusr1():
  """Catch SIGUSR1 and print a stack trace."""
  # Windows doesn't define SIGUSR1.
  if not hasattr(signal, 'SIGUSR1'):
    return

  def PrintDiagnostics(_, stack_frame):
    exception_string = 'SIGUSR1 received, printed stack trace'
    exception_formatter.PrintFormattedFrame(stack_frame, exception_string)
  signal.signal(signal.SIGUSR1, PrintDiagnostics)


def InstallTerminationHook():
  """Catch SIGTERM, print a stack trace, and exit."""
  def PrintStackAndExit(sig, stack_frame):
    exception_string = 'Received signal %s, exiting' % sig
    exception_formatter.PrintFormattedFrame(stack_frame, exception_string)
    sys.exit(-1)
  signal.signal(signal.SIGTERM, PrintStackAndExit)
