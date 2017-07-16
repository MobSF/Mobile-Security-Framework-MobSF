#!/usr/bin/env python
#
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This is a script developers can use to set-up their workstation to let
# Telemetry read the CPU's Model Specific Registers in order to get power
# measurements. It can check if reading from MSRs is possible as any user, but
# must run as root to make changes. Not all changes are sticky, so one has to
# re-run this script after each reboot.
#
# This script is currently Debian/Ubuntu specific.

import os
import subprocess
import sys

MSR_DEV_FILE_PATH = '/dev/cpu/0/msr'
RDMSR_PATH = '/usr/sbin/rdmsr'

def _Usage(prog_name):
  """Print a help message."""
  print 'Run "%s" as a regular user to check if reading from the MSR ' \
      'is possible.' % prog_name
  print 'Run "%s enable" as root to automatically set up reading from ' \
      'the MSR.' % prog_name


def _CheckMsrKernelModule():
  """Return whether the 'msr' kernel module is loaded."""
  proc = subprocess.Popen('/sbin/lsmod', stdout=subprocess.PIPE)
  stdout = proc.communicate()[0]
  ret = proc.wait()
  if ret != 0:
    raise OSError('lsmod failed')

  if not any([line.startswith('msr ') for line in stdout.splitlines()]):
    print 'Error: MSR module not loaded.'
    return False

  return True


def _CheckMsrDevNodes():
  """Check whether the MSR /dev files have the right permissions."""
  if not os.path.exists(MSR_DEV_FILE_PATH):
    print 'Error: %s does not exist.' % MSR_DEV_FILE_PATH
    return False

  if not os.access(MSR_DEV_FILE_PATH, os.R_OK):
    print 'Error: Cannot read from %s' % MSR_DEV_FILE_PATH
    return False

  return True


def _CheckRdmsr():
  """Check and make sure /usr/sbin/rdmsr is set up correctly."""
  if not os.access(RDMSR_PATH, os.X_OK):
    print 'Error: %s missing or not executable.' % RDMSR_PATH
    return False

  proc = subprocess.Popen(['/sbin/getcap', RDMSR_PATH], stdout=subprocess.PIPE)
  stdout = proc.communicate()[0]
  ret = proc.wait()
  if ret != 0:
    raise OSError('getcap failed')

  if not 'cap_sys_rawio+ep' in stdout:
    print 'Error: /usr/sbin/rdmsr needs RAWIO capability.'
    return False

  return True


def _RunAllChecks():
  """Check to make sure it is possible to read from the MSRs."""
  if os.geteuid() == 0:
    print 'WARNING: Running as root, msr permission check likely inaccurate.'

  has_dev_node = _CheckMsrDevNodes() if _CheckMsrKernelModule() else False
  has_rdmsr = _CheckRdmsr()
  return has_dev_node and has_rdmsr


def _EnableMsr(prog_name):
  """Do all the setup needed to pass _RunAllChecks().

  Needs to run as root."""
  if os.geteuid() != 0:
    print 'Error: Must run "%s enable" as root.' % prog_name
    return False

  print 'Loading msr kernel module.'
  ret = subprocess.call(['/sbin/modprobe', 'msr'])
  if ret != 0:
    print 'Error: Cannot load msr module.'
    return False

  print 'Running chmod on %s.' % MSR_DEV_FILE_PATH
  ret = subprocess.call(['/bin/chmod', 'a+r', MSR_DEV_FILE_PATH])
  if ret != 0:
    print 'Error: Cannot chmod %s.' % MSR_DEV_FILE_PATH
    return False

  if not os.access(RDMSR_PATH, os.F_OK):
    print 'Need to install the msr-tools package.'
    ret = subprocess.call(['/usr/bin/apt-get', 'install', '-y', 'msr-tools'])
    if ret != 0:
      print 'Error: Did not successfully install msr-tools.'
      return False

  print 'Running setcap on %s.' % RDMSR_PATH
  ret = subprocess.call(['/sbin/setcap', 'cap_sys_rawio+ep', RDMSR_PATH])
  if ret != 0:
    print 'Error: Cannot give /usr/sbin/rdmsr RAWIO capability.'
    return False

  return True


def main(prog_name, argv):
  if len(argv) == 0:
    if _RunAllChecks():
      print 'Check succeeded'
      return 0

    print 'Check failed, try running "%s enable" as root to fix.' % prog_name
    return 1

  if len(argv) == 1:
    if argv[0] == 'enable':
      return 0 if _EnableMsr(prog_name) else 1

    print 'Error: Unknown sub-command %s' % argv[0]
    _Usage(prog_name)
    return 1

  print 'Error: Bad number of arguments'
  _Usage(prog_name)
  return 1


if '__main__' == __name__:
  sys.exit(main(os.path.basename(sys.argv[0]), sys.argv[1:]))
