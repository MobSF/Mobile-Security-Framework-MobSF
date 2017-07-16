# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import distutils.spawn
import logging
import os
import re
import stat
import subprocess
import sys

from telemetry.internal.platform import desktop_platform_backend
from telemetry.internal.util import ps_util


def _BinaryExistsInSudoersFiles(path, sudoers_file_contents):
  """Returns True if the binary in |path| features in the sudoers file.
  """
  for line in sudoers_file_contents.splitlines():
    if re.match(r'\s*\(.+\) NOPASSWD: %s(\s\S+)*$' % re.escape(path), line):
      return True
  return False


def _CanRunElevatedWithSudo(path):
  """Returns True if the binary at |path| appears in the sudoers file.
  If this function returns true then the binary at |path| can be run via sudo
  without prompting for a password.
  """
  sudoers = subprocess.check_output(['/usr/bin/sudo', '-l'])
  return _BinaryExistsInSudoersFiles(path, sudoers)


class PosixPlatformBackend(desktop_platform_backend.DesktopPlatformBackend):

  # This is an abstract class. It is OK to have abstract methods.
  # pylint: disable=abstract-method

  def HasRootAccess(self):
    return os.getuid() == 0

  def RunCommand(self, args):
    return subprocess.Popen(args, stdout=subprocess.PIPE).communicate()[0]

  def GetFileContents(self, path):
    with open(path, 'r') as f:
      return f.read()

  def GetPsOutput(self, columns, pid=None):
    """Returns output of the 'ps' command as a list of lines.
    Subclass should override this function.

    Args:
      columns: A list of require columns, e.g., ['pid', 'pss'].
      pid: If not None, returns only the information of the process
         with the pid.
    """
    return ps_util.GetPsOutputWithPlatformBackend(self, columns, pid)

  def _GetTopOutput(self, pid, columns):
    """Returns output of the 'top' command as a list of lines.

    Args:
      pid: pid of process to examine.
      columns: A list of require columns, e.g., ['idlew', 'vsize'].
    """
    args = ['top']
    args.extend(['-pid', str(pid), '-l', '1', '-s', '0', '-stats',
        ','.join(columns)])
    return self.RunCommand(args).splitlines()

  def GetChildPids(self, pid):
    """Returns a list of child pids of |pid|."""
    ps_output = self.GetPsOutput(['pid', 'ppid', 'state'])
    ps_line_re = re.compile(
        r'\s*(?P<pid>\d+)\s*(?P<ppid>\d+)\s*(?P<state>\S*)\s*')
    processes = []
    for pid_ppid_state in ps_output:
      m = ps_line_re.match(pid_ppid_state)
      assert m, 'Did not understand ps output: %s' % pid_ppid_state
      processes.append((m.group('pid'), m.group('ppid'), m.group('state')))
    return ps_util.GetChildPids(processes, pid)

  def GetCommandLine(self, pid):
    command = self.GetPsOutput(['command'], pid)
    return command[0] if command else None

  def CanLaunchApplication(self, application):
    return bool(distutils.spawn.find_executable(application))

  def IsApplicationRunning(self, application):
    ps_output = self.GetPsOutput(['command'])
    application_re = re.compile(
        r'(.*%s|^)%s(\s|$)' % (os.path.sep, application))
    return any(application_re.match(cmd) for cmd in ps_output)

  def LaunchApplication(
      self, application, parameters=None, elevate_privilege=False):
    assert application, 'Must specify application to launch'

    if os.path.sep not in application:
      application = distutils.spawn.find_executable(application)
      assert application, 'Failed to find application in path'

    args = [application]

    if parameters:
      assert isinstance(parameters, list), 'parameters must be a list'
      args += parameters

    def IsElevated():
      """ Returns True if the current process is elevated via sudo i.e. running
      sudo will not prompt for a password. Returns False if not authenticated
      via sudo or if telemetry is run on a non-interactive TTY."""
      # `sudo -v` will always fail if run from a non-interactive TTY.
      p = subprocess.Popen(
          ['/usr/bin/sudo', '-nv'], stdin=subprocess.PIPE,
          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      stdout = p.communicate()[0]
      # Some versions of sudo set the returncode based on whether sudo requires
      # a password currently. Other versions return output when password is
      # required and no output when the user is already authenticated.
      return not p.returncode and not stdout

    def IsSetUID(path):
      """Returns True if the binary at |path| has the setuid bit set."""
      return (os.stat(path).st_mode & stat.S_ISUID) == stat.S_ISUID

    if elevate_privilege and not IsSetUID(application):
      args = ['/usr/bin/sudo'] + args
      if not _CanRunElevatedWithSudo(application) and not IsElevated():
        if not sys.stdout.isatty():
          # Without an interactive terminal (or a configured 'askpass', but
          # that is rarely relevant), there's no way to prompt the user for
          # sudo. Fail with a helpful error message. For more information, see:
          #   https://code.google.com/p/chromium/issues/detail?id=426720
          text = ('Telemetry needs to run %s with elevated privileges, but the '
                 'setuid bit is not set and there is no interactive terminal '
                 'for a prompt. Please ask an administrator to set the setuid '
                 'bit on this executable and ensure that it is owned by a user '
                 'with the necessary privileges. Aborting.' % application)
          print text
          raise Exception(text)
        # Else, there is a tty that can be used for a useful interactive prompt.
        print ('Telemetry needs to run %s under sudo. Please authenticate.' %
               application)
        # Synchronously authenticate.
        subprocess.check_call(['/usr/bin/sudo', '-v'])

    stderror_destination = subprocess.PIPE
    if logging.getLogger().isEnabledFor(logging.DEBUG):
      stderror_destination = None

    return subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=stderror_destination)
