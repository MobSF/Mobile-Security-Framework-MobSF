# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A wrapper around ssh for common operations on a CrOS-based device"""
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile

# Some developers' workflow includes running the Chrome process from
# /usr/local/... instead of the default location. We have to check for both
# paths in order to support this workflow.
_CHROME_PROCESS_REGEX = [re.compile(r'^/opt/google/chrome/chrome '),
                         re.compile(r'^/usr/local/?.*/chrome/chrome ')]


def RunCmd(args, cwd=None, quiet=False):
  """Opens a subprocess to execute a program and returns its return value.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.

  Returns:
    Return code from the command execution.
  """
  if not quiet:
    logging.debug(' '.join(args) + ' ' + (cwd or ''))
  with open(os.devnull, 'w') as devnull:
    p = subprocess.Popen(args=args,
                         cwd=cwd,
                         stdout=devnull,
                         stderr=devnull,
                         stdin=devnull,
                         shell=False)
    return p.wait()


def GetAllCmdOutput(args, cwd=None, quiet=False):
  """Open a subprocess to execute a program and returns its output.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.

  Returns:
    Captures and returns the command's stdout.
    Prints the command's stderr to logger (which defaults to stdout).
  """
  if not quiet:
    logging.debug(' '.join(args) + ' ' + (cwd or ''))
  with open(os.devnull, 'w') as devnull:
    p = subprocess.Popen(args=args,
                         cwd=cwd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=devnull)
    stdout, stderr = p.communicate()
    if not quiet:
      logging.debug(' > stdout=[%s], stderr=[%s]', stdout, stderr)
    return stdout, stderr


def HasSSH():
  try:
    RunCmd(['ssh'], quiet=True)
    RunCmd(['scp'], quiet=True)
    logging.debug("HasSSH()->True")
    return True
  except OSError:
    logging.debug("HasSSH()->False")
    return False


class LoginException(Exception):
  pass


class KeylessLoginRequiredException(LoginException):
  pass


class DNSFailureException(LoginException):
  pass


class CrOSInterface(object):

  def __init__(self, hostname=None, ssh_port=None, ssh_identity=None):
    self._hostname = hostname
    self._ssh_port = ssh_port

    # List of ports generated from GetRemotePort() that may not be in use yet.
    self._reserved_ports = []

    if self.local:
      return

    self._ssh_identity = None
    self._ssh_args = ['-o ConnectTimeout=5', '-o StrictHostKeyChecking=no',
                      '-o KbdInteractiveAuthentication=no',
                      '-o PreferredAuthentications=publickey',
                      '-o UserKnownHostsFile=/dev/null', '-o ControlMaster=no']

    if ssh_identity:
      self._ssh_identity = os.path.abspath(os.path.expanduser(ssh_identity))
      os.chmod(self._ssh_identity, stat.S_IREAD)

    # Establish master SSH connection using ControlPersist.
    # Since only one test will be run on a remote host at a time,
    # the control socket filename can be telemetry@hostname.
    self._ssh_control_file = '/tmp/' + 'telemetry' + '@' + hostname
    with open(os.devnull, 'w') as devnull:
      subprocess.call(
          self.FormSSHCommandLine(['-M', '-o ControlPersist=yes']),
          stdin=devnull,
          stdout=devnull,
          stderr=devnull)

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self.CloseConnection()

  @property
  def local(self):
    return not self._hostname

  @property
  def hostname(self):
    return self._hostname

  @property
  def ssh_port(self):
    return self._ssh_port

  def FormSSHCommandLine(self, args, extra_ssh_args=None):
    """Constructs a subprocess-suitable command line for `ssh'.
    """
    if self.local:
      # We run the command through the shell locally for consistency with
      # how commands are run through SSH (crbug.com/239161). This work
      # around will be unnecessary once we implement a persistent SSH
      # connection to run remote commands (crbug.com/239607).
      return ['sh', '-c', " ".join(args)]

    full_args = ['ssh', '-o ForwardX11=no', '-o ForwardX11Trusted=no', '-n',
                 '-S', self._ssh_control_file] + self._ssh_args
    if self._ssh_identity is not None:
      full_args.extend(['-i', self._ssh_identity])
    if extra_ssh_args:
      full_args.extend(extra_ssh_args)
    full_args.append('root@%s' % self._hostname)
    full_args.append('-p%d' % self._ssh_port)
    full_args.extend(args)
    return full_args

  def _FormSCPCommandLine(self, src, dst, extra_scp_args=None):
    """Constructs a subprocess-suitable command line for `scp'.

    Note: this function is not designed to work with IPv6 addresses, which need
    to have their addresses enclosed in brackets and a '-6' flag supplied
    in order to be properly parsed by `scp'.
    """
    assert not self.local, "Cannot use SCP on local target."

    args = ['scp', '-P', str(self._ssh_port)] + self._ssh_args
    if self._ssh_identity:
      args.extend(['-i', self._ssh_identity])
    if extra_scp_args:
      args.extend(extra_scp_args)
    args += [src, dst]
    return args

  def _FormSCPToRemote(self,
                       source,
                       remote_dest,
                       extra_scp_args=None,
                       user='root'):
    return self._FormSCPCommandLine(source,
                                    '%s@%s:%s' % (user, self._hostname,
                                                  remote_dest),
                                    extra_scp_args=extra_scp_args)

  def _FormSCPFromRemote(self,
                         remote_source,
                         dest,
                         extra_scp_args=None,
                         user='root'):
    return self._FormSCPCommandLine('%s@%s:%s' % (user, self._hostname,
                                                  remote_source),
                                    dest,
                                    extra_scp_args=extra_scp_args)

  def _RemoveSSHWarnings(self, toClean):
    """Removes specific ssh warning lines from a string.

    Args:
      toClean: A string that may be containing multiple lines.

    Returns:
      A copy of toClean with all the Warning lines removed.
    """
    # Remove the Warning about connecting to a new host for the first time.
    return re.sub(
        r'Warning: Permanently added [^\n]* to the list of known hosts.\s\n',
        '', toClean)

  def RunCmdOnDevice(self, args, cwd=None, quiet=False):
    stdout, stderr = GetAllCmdOutput(
        self.FormSSHCommandLine(args),
        cwd,
        quiet=quiet)
    # The initial login will add the host to the hosts file but will also print
    # a warning to stderr that we need to remove.
    stderr = self._RemoveSSHWarnings(stderr)
    return stdout, stderr

  def TryLogin(self):
    logging.debug('TryLogin()')
    assert not self.local
    stdout, stderr = self.RunCmdOnDevice(['echo', '$USER'], quiet=True)
    if stderr != '':
      if 'Host key verification failed' in stderr:
        raise LoginException(('%s host key verification failed. ' +
                              'SSH to it manually to fix connectivity.') %
                             self._hostname)
      if 'Operation timed out' in stderr:
        raise LoginException('Timed out while logging into %s' % self._hostname)
      if 'UNPROTECTED PRIVATE KEY FILE!' in stderr:
        raise LoginException('Permissions for %s are too open. To fix this,\n'
                             'chmod 600 %s' % (self._ssh_identity,
                                               self._ssh_identity))
      if 'Permission denied (publickey,keyboard-interactive)' in stderr:
        raise KeylessLoginRequiredException('Need to set up ssh auth for %s' %
                                            self._hostname)
      if 'Could not resolve hostname' in stderr:
        raise DNSFailureException('Unable to resolve the hostname for: %s' %
                                  self._hostname)
      raise LoginException('While logging into %s, got %s' % (self._hostname,
                                                              stderr))
    if stdout != 'root\n':
      raise LoginException('Logged into %s, expected $USER=root, but got %s.' %
                           (self._hostname, stdout))

  def FileExistsOnDevice(self, file_name):
    if self.local:
      return os.path.exists(file_name)

    stdout, stderr = self.RunCmdOnDevice(
        [
            'if', 'test', '-e', file_name, ';', 'then', 'echo', '1', ';', 'fi'
        ],
        quiet=True)
    if stderr != '':
      if "Connection timed out" in stderr:
        raise OSError('Machine wasn\'t responding to ssh: %s' % stderr)
      raise OSError('Unexpected error: %s' % stderr)
    exists = stdout == '1\n'
    logging.debug("FileExistsOnDevice(<text>, %s)->%s" % (file_name, exists))
    return exists

  def PushFile(self, filename, remote_filename):
    if self.local:
      args = ['cp', '-r', filename, remote_filename]
      stdout, stderr = GetAllCmdOutput(args, quiet=True)
      if stderr != '':
        raise OSError('No such file or directory %s' % stderr)
      return

    args = self._FormSCPToRemote(
        os.path.abspath(filename),
        remote_filename,
        extra_scp_args=['-r'])

    stdout, stderr = GetAllCmdOutput(args, quiet=True)
    stderr = self._RemoveSSHWarnings(stderr)
    if stderr != '':
      raise OSError('No such file or directory %s' % stderr)

  def PushContents(self, text, remote_filename):
    logging.debug("PushContents(<text>, %s)" % remote_filename)
    with tempfile.NamedTemporaryFile() as f:
      f.write(text)
      f.flush()
      self.PushFile(f.name, remote_filename)

  def GetFile(self, filename, destfile=None):
    """Copies a local file |filename| to |destfile| on the device.

    Args:
      filename: The name of the local source file.
      destfile: The name of the file to copy to, and if it is not specified
        then it is the basename of the source file.

    """
    logging.debug("GetFile(%s, %s)" % (filename, destfile))
    if self.local:
      if destfile is not None and destfile != filename:
        shutil.copyfile(filename, destfile)
        return
      else:
        raise OSError('No such file or directory %s' % filename)

    if destfile is None:
      destfile = os.path.basename(filename)
    args = self._FormSCPFromRemote(filename, os.path.abspath(destfile))

    stdout, stderr = GetAllCmdOutput(args, quiet=True)
    stderr = self._RemoveSSHWarnings(stderr)
    if stderr != '':
      raise OSError('No such file or directory %s' % stderr)

  def GetFileContents(self, filename):
    """Get the contents of a file on the device.

    Args:
      filename: The name of the file on the device.

    Returns:
      A string containing the contents of the file.
    """
    with tempfile.NamedTemporaryFile() as t:
      self.GetFile(filename, t.name)
      with open(t.name, 'r') as f2:
        res = f2.read()
        logging.debug("GetFileContents(%s)->%s" % (filename, res))
        return res

  def HasSystemd(self):
    """Return True or False to indicate if systemd is used.

    Note: This function checks to see if the 'systemctl' utilitary
    is installed. This is only installed along with the systemd daemon.
    """
    _, stderr = self.RunCmdOnDevice(['systemctl'], quiet=True)
    return stderr == ''

  def ListProcesses(self):
    """Returns (pid, cmd, ppid, state) of all processes on the device."""
    stdout, stderr = self.RunCmdOnDevice(
        [
            '/bin/ps', '--no-headers', '-A', '-o', 'pid,ppid,args:4096,state'
        ],
        quiet=True)
    assert stderr == '', stderr
    procs = []
    for l in stdout.split('\n'):
      if l == '':
        continue
      m = re.match(r'^\s*(\d+)\s+(\d+)\s+(.+)\s+(.+)', l, re.DOTALL)
      assert m
      procs.append((int(m.group(1)), m.group(3).rstrip(), int(m.group(2)),
                    m.group(4)))
    logging.debug("ListProcesses(<predicate>)->[%i processes]" % len(procs))
    return procs

  def _GetSessionManagerPid(self, procs):
    """Returns the pid of the session_manager process, given the list of
    processes."""
    for pid, process, _, _ in procs:
      argv = process.split()
      if argv and os.path.basename(argv[0]) == 'session_manager':
        return pid
    return None

  def GetChromeProcess(self):
    """Locates the the main chrome browser process.

    Chrome on cros is usually in /opt/google/chrome, but could be in
    /usr/local/ for developer workflows - debug chrome is too large to fit on
    rootfs.

    Chrome spawns multiple processes for renderers. pids wrap around after they
    are exhausted so looking for the smallest pid is not always correct. We
    locate the session_manager's pid, and look for the chrome process that's an
    immediate child. This is the main browser process.
    """
    procs = self.ListProcesses()
    session_manager_pid = self._GetSessionManagerPid(procs)
    if not session_manager_pid:
      return None

    # Find the chrome process that is the child of the session_manager.
    for pid, process, ppid, _ in procs:
      if ppid != session_manager_pid:
        continue
      for regex in _CHROME_PROCESS_REGEX:
        path_match = re.match(regex, process)
        if path_match is not None:
          return {'pid': pid, 'path': path_match.group(), 'args': process}
    return None

  def GetChromePid(self):
    """Returns pid of main chrome browser process."""
    result = self.GetChromeProcess()
    if result and 'pid' in result:
      return result['pid']
    return None

  def RmRF(self, filename):
    logging.debug("rm -rf %s" % filename)
    self.RunCmdOnDevice(['rm', '-rf', filename], quiet=True)

  def Chown(self, filename):
    self.RunCmdOnDevice(['chown', '-R', 'chronos:chronos', filename])

  def KillAllMatching(self, predicate):
    kills = ['kill', '-KILL']
    for pid, cmd, _, _ in self.ListProcesses():
      if predicate(cmd):
        logging.info('Killing %s, pid %d' % cmd, pid)
        kills.append(pid)
    logging.debug("KillAllMatching(<predicate>)->%i" % (len(kills) - 2))
    if len(kills) > 2:
      self.RunCmdOnDevice(kills, quiet=True)
    return len(kills) - 2

  def IsServiceRunning(self, service_name):
    """Check with the init daemon if the given service is running."""
    if self.HasSystemd():
      # Querying for the pid of the service will return 'MainPID=0' if
      # the service is not running.
      stdout, stderr = self.RunCmdOnDevice(
          ['systemctl', 'show', '-p', 'MainPID', service_name], quiet=True)
      running = int(stdout.split('=')[1]) != 0
    else:
      stdout, stderr = self.RunCmdOnDevice(['status', service_name], quiet=True)
      running = 'running, process' in stdout
    assert stderr == '', stderr
    logging.debug("IsServiceRunning(%s)->%s" % (service_name, running))
    return running

  def GetRemotePort(self):
    netstat = self.RunCmdOnDevice(['netstat', '-ant'])
    netstat = netstat[0].split('\n')
    ports_in_use = []

    for line in netstat[2:]:
      if not line:
        continue
      address_in_use = line.split()[3]
      port_in_use = address_in_use.split(':')[-1]
      ports_in_use.append(int(port_in_use))

    ports_in_use.extend(self._reserved_ports)

    new_port = sorted(ports_in_use)[-1] + 1
    self._reserved_ports.append(new_port)

    return new_port

  def IsHTTPServerRunningOnPort(self, port):
    wget_output = self.RunCmdOnDevice(['wget', 'localhost:%i' % (port), '-T1',
                                       '-t1'])

    if 'Connection refused' in wget_output[1]:
      return False

    return True

  def _GetMountSourceAndTarget(self, path):
    df_out, _ = self.RunCmdOnDevice(['/bin/df', '--output=source,target', path])
    df_ary = df_out.split('\n')
    # 3 lines for title, mount info, and empty line.
    if len(df_ary) == 3:
      line_ary = df_ary[1].split()
      return line_ary if len(line_ary) == 2 else None
    return None

  def FilesystemMountedAt(self, path):
    """Returns the filesystem mounted at |path|"""
    mount_info = self._GetMountSourceAndTarget(path)
    return mount_info[0] if mount_info else None

  def CryptohomePath(self, user):
    """Returns the cryptohome mount point for |user|."""
    stdout, stderr = self.RunCmdOnDevice(['cryptohome-path', 'user', "'%s'" %
                                          user])
    if stderr != '':
      raise OSError('cryptohome-path failed: %s' % stderr)
    return stdout.rstrip()

  def IsCryptohomeMounted(self, username, is_guest):
    """Returns True iff |user|'s cryptohome is mounted."""
    profile_path = self.CryptohomePath(username)
    mount_info = self._GetMountSourceAndTarget(profile_path)
    if mount_info:
      # Checks if the filesytem at |profile_path| is mounted on |profile_path|
      # itself. Before mounting cryptohome, it shows an upper directory (/home).
      is_guestfs = (mount_info[0] == 'guestfs')
      return is_guestfs == is_guest and mount_info[1] == profile_path
    return False

  def TakeScreenshot(self, file_path):
    stdout, stderr = self.RunCmdOnDevice(
        ['/usr/local/autotest/bin/screenshot.py', file_path])
    return stdout == '' and stderr == ''

  def TakeScreenshotWithPrefix(self, screenshot_prefix):
    """Takes a screenshot, useful for debugging failures."""
    # TODO(achuith): Find a better location for screenshots. Cros autotests
    # upload everything in /var/log so use /var/log/screenshots for now.
    SCREENSHOT_DIR = '/var/log/screenshots/'
    SCREENSHOT_EXT = '.png'

    self.RunCmdOnDevice(['mkdir', '-p', SCREENSHOT_DIR])
    # Large number of screenshots can increase hardware lab bandwidth
    # dramatically, so keep this number low. crbug.com/524814.
    for i in xrange(2):
      screenshot_file = ('%s%s-%d%s' %
                         (SCREENSHOT_DIR, screenshot_prefix, i, SCREENSHOT_EXT))
      if not self.FileExistsOnDevice(screenshot_file):
        return self.TakeScreenshot(screenshot_file)
    logging.warning('screenshot directory full.')
    return False

  def GetArchName(self):
    return self.RunCmdOnDevice(['uname', '-m'])[0]

  def IsRunningOnVM(self):
    return self.RunCmdOnDevice(['crossystem', 'inside_vm'])[0] != '0'

  def LsbReleaseValue(self, key, default):
    """/etc/lsb-release is a file with key=value pairs."""
    lines = self.GetFileContents('/etc/lsb-release').split('\n')
    for l in lines:
      m = re.match(r'([^=]*)=(.*)', l)
      if m and m.group(1) == key:
        return m.group(2)
    return default

  def GetDeviceTypeName(self):
    """DEVICETYPE in /etc/lsb-release is CHROMEBOOK, CHROMEBIT, etc."""
    return self.LsbReleaseValue(key='DEVICETYPE', default='CHROMEBOOK')

  def RestartUI(self, clear_enterprise_policy):
    logging.info('(Re)starting the ui (logs the user out)')
    start_cmd = ['start', 'ui']
    restart_cmd = ['restart', 'ui']
    stop_cmd = ['stop', 'ui']
    if self.HasSystemd():
      start_cmd.insert(0, 'systemctl')
      restart_cmd.insert(0, 'systemctl')
      stop_cmd.insert(0, 'systemctl')
    if clear_enterprise_policy:
      self.RunCmdOnDevice(stop_cmd)
      self.RmRF('/var/lib/whitelist/*')
      self.RmRF(r'/home/chronos/Local\ State')

    if self.IsServiceRunning('ui'):
      self.RunCmdOnDevice(restart_cmd)
    else:
      self.RunCmdOnDevice(start_cmd)

  def CloseConnection(self):
    if not self.local:
      with open(os.devnull, 'w') as devnull:
        subprocess.call(
            self.FormSSHCommandLine(['-O', 'exit', self._hostname]),
            stdout=devnull,
            stderr=devnull)
