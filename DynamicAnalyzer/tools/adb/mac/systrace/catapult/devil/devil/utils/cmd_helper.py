# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A wrapper for subprocess to make calling shell commands easier."""

import logging
import os
import pipes
import select
import signal
import string
import StringIO
import subprocess
import sys
import time

# fcntl is not available on Windows.
try:
  import fcntl
except ImportError:
  fcntl = None

logger = logging.getLogger(__name__)

_SafeShellChars = frozenset(string.ascii_letters + string.digits + '@%_-+=:,./')


def SingleQuote(s):
  """Return an shell-escaped version of the string using single quotes.

  Reliably quote a string which may contain unsafe characters (e.g. space,
  quote, or other special characters such as '$').

  The returned value can be used in a shell command line as one token that gets
  to be interpreted literally.

  Args:
    s: The string to quote.

  Return:
    The string quoted using single quotes.
  """
  return pipes.quote(s)


def DoubleQuote(s):
  """Return an shell-escaped version of the string using double quotes.

  Reliably quote a string which may contain unsafe characters (e.g. space
  or quote characters), while retaining some shell features such as variable
  interpolation.

  The returned value can be used in a shell command line as one token that gets
  to be further interpreted by the shell.

  The set of characters that retain their special meaning may depend on the
  shell implementation. This set usually includes: '$', '`', '\', '!', '*',
  and '@'.

  Args:
    s: The string to quote.

  Return:
    The string quoted using double quotes.
  """
  if not s:
    return '""'
  elif all(c in _SafeShellChars for c in s):
    return s
  else:
    return '"' + s.replace('"', '\\"') + '"'


def ShrinkToSnippet(cmd_parts, var_name, var_value):
  """Constructs a shell snippet for a command using a variable to shrink it.

  Takes into account all quoting that needs to happen.

  Args:
    cmd_parts: A list of command arguments.
    var_name: The variable that holds var_value.
    var_value: The string to replace in cmd_parts with $var_name

  Returns:
    A shell snippet that does not include setting the variable.
  """
  def shrink(value):
    parts = (x and SingleQuote(x) for x in value.split(var_value))
    with_substitutions = ('"$%s"' % var_name).join(parts)
    return with_substitutions or "''"

  return ' '.join(shrink(part) for part in cmd_parts)


def Popen(args, stdout=None, stderr=None, shell=None, cwd=None, env=None):
  # preexec_fn isn't supported on windows.
  if sys.platform == 'win32':
    preexec_fn = None
  else:
    preexec_fn = lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL)

  return subprocess.Popen(
      args=args, cwd=cwd, stdout=stdout, stderr=stderr,
      shell=shell, close_fds=True, env=env, preexec_fn=preexec_fn)


def Call(args, stdout=None, stderr=None, shell=None, cwd=None, env=None):
  pipe = Popen(args, stdout=stdout, stderr=stderr, shell=shell, cwd=cwd,
               env=env)
  pipe.communicate()
  return pipe.wait()


def RunCmd(args, cwd=None):
  """Opens a subprocess to execute a program and returns its return value.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.

  Returns:
    Return code from the command execution.
  """
  logger.info(str(args) + ' ' + (cwd or ''))
  return Call(args, cwd=cwd)


def GetCmdOutput(args, cwd=None, shell=False):
  """Open a subprocess to execute a program and returns its output.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command.

  Returns:
    Captures and returns the command's stdout.
    Prints the command's stderr to logger (which defaults to stdout).
  """
  (_, output) = GetCmdStatusAndOutput(args, cwd, shell)
  return output


def _ValidateAndLogCommand(args, cwd, shell):
  if isinstance(args, basestring):
    if not shell:
      raise Exception('string args must be run with shell=True')
  else:
    if shell:
      raise Exception('array args must be run with shell=False')
    args = ' '.join(SingleQuote(c) for c in args)
  if cwd is None:
    cwd = ''
  else:
    cwd = ':' + cwd
  logger.info('[host]%s> %s', cwd, args)
  return args


def GetCmdStatusAndOutput(args, cwd=None, shell=False):
  """Executes a subprocess and returns its exit code and output.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command. Must be True if args
      is a string and False if args is a sequence.

  Returns:
    The 2-tuple (exit code, output).
  """
  status, stdout, stderr = GetCmdStatusOutputAndError(
      args, cwd=cwd, shell=shell)

  if stderr:
    logger.critical('STDERR: %s', stderr)
  logger.debug('STDOUT: %s%s', stdout[:4096].rstrip(),
               '<truncated>' if len(stdout) > 4096 else '')
  return (status, stdout)


def GetCmdStatusOutputAndError(args, cwd=None, shell=False):
  """Executes a subprocess and returns its exit code, output, and errors.

  Args:
    args: A string or a sequence of program arguments. The program to execute is
      the string or the first item in the args sequence.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command. Must be True if args
      is a string and False if args is a sequence.

  Returns:
    The 2-tuple (exit code, output).
  """
  _ValidateAndLogCommand(args, cwd, shell)
  pipe = Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               shell=shell, cwd=cwd)
  stdout, stderr = pipe.communicate()
  return (pipe.returncode, stdout, stderr)


class TimeoutError(Exception):
  """Module-specific timeout exception."""

  def __init__(self, output=None):
    super(TimeoutError, self).__init__()
    self._output = output

  @property
  def output(self):
    return self._output


def _IterProcessStdout(process, iter_timeout=None, timeout=None,
                       buffer_size=4096, poll_interval=1):
  """Iterate over a process's stdout.

  This is intentionally not public.

  Args:
    process: The process in question.
    iter_timeout: An optional length of time, in seconds, to wait in
      between each iteration. If no output is received in the given
      time, this generator will yield None.
    timeout: An optional length of time, in seconds, during which
      the process must finish. If it fails to do so, a TimeoutError
      will be raised.
    buffer_size: The maximum number of bytes to read (and thus yield) at once.
    poll_interval: The length of time to wait in calls to `select.select`.
      If iter_timeout is set, the remaining length of time in the iteration
      may take precedence.
  Raises:
    TimeoutError: if timeout is set and the process does not complete.
  Yields:
    basestrings of data or None.
  """

  assert fcntl, 'fcntl module is required'
  try:
    # Enable non-blocking reads from the child's stdout.
    child_fd = process.stdout.fileno()
    fl = fcntl.fcntl(child_fd, fcntl.F_GETFL)
    fcntl.fcntl(child_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    end_time = (time.time() + timeout) if timeout else None
    iter_end_time = (time.time() + iter_timeout) if iter_timeout else None

    while True:
      if end_time and time.time() > end_time:
        raise TimeoutError()
      if iter_end_time and time.time() > iter_end_time:
        yield None
        iter_end_time = time.time() + iter_timeout

      if iter_end_time:
        iter_aware_poll_interval = min(
            poll_interval,
            max(0, iter_end_time - time.time()))
      else:
        iter_aware_poll_interval = poll_interval

      read_fds, _, _ = select.select(
          [child_fd], [], [], iter_aware_poll_interval)
      if child_fd in read_fds:
        data = os.read(child_fd, buffer_size)
        if not data:
          break
        yield data
      if process.poll() is not None:
        break
  finally:
    try:
      if process.returncode is None:
        # Make sure the process doesn't stick around if we fail with an
        # exception.
        process.kill()
    except OSError:
      pass
    process.wait()


def GetCmdStatusAndOutputWithTimeout(args, timeout, cwd=None, shell=False,
                                     logfile=None):
  """Executes a subprocess with a timeout.

  Args:
    args: List of arguments to the program, the program to execute is the first
      element.
    timeout: the timeout in seconds or None to wait forever.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command. Must be True if args
      is a string and False if args is a sequence.
    logfile: Optional file-like object that will receive output from the
      command as it is running.

  Returns:
    The 2-tuple (exit code, output).
  Raises:
    TimeoutError on timeout.
  """
  _ValidateAndLogCommand(args, cwd, shell)
  output = StringIO.StringIO()
  process = Popen(args, cwd=cwd, shell=shell, stdout=subprocess.PIPE,
                  stderr=subprocess.STDOUT)
  try:
    for data in _IterProcessStdout(process, timeout=timeout):
      if logfile:
        logfile.write(data)
      output.write(data)
  except TimeoutError:
    raise TimeoutError(output.getvalue())

  str_output = output.getvalue()
  logger.debug('STDOUT+STDERR: %s%s', str_output[:4096].rstrip(),
               '<truncated>' if len(str_output) > 4096 else '')
  return process.returncode, str_output


def IterCmdOutputLines(args, iter_timeout=None, timeout=None, cwd=None,
                       shell=False, check_status=True):
  """Executes a subprocess and continuously yields lines from its output.

  Args:
    args: List of arguments to the program, the program to execute is the first
      element.
    iter_timeout: Timeout for each iteration, in seconds.
    timeout: Timeout for the entire command, in seconds.
    cwd: If not None, the subprocess's current directory will be changed to
      |cwd| before it's executed.
    shell: Whether to execute args as a shell command. Must be True if args
      is a string and False if args is a sequence.
    check_status: A boolean indicating whether to check the exit status of the
      process after all output has been read.
  Yields:
    The output of the subprocess, line by line.

  Raises:
    CalledProcessError if check_status is True and the process exited with a
      non-zero exit status.
  """
  cmd = _ValidateAndLogCommand(args, cwd, shell)
  process = Popen(args, cwd=cwd, shell=shell, stdout=subprocess.PIPE,
                  stderr=subprocess.STDOUT)
  return _IterCmdOutputLines(
      process, cmd, iter_timeout=iter_timeout, timeout=timeout,
      check_status=check_status)

def _IterCmdOutputLines(process, cmd, iter_timeout=None, timeout=None,
                        check_status=True):
  buffer_output = ''

  iter_end = None
  cur_iter_timeout = None
  if iter_timeout:
    iter_end = time.time() + iter_timeout
    cur_iter_timeout = iter_timeout

  for data in _IterProcessStdout(process, iter_timeout=cur_iter_timeout,
                                 timeout=timeout):
    if iter_timeout:
      # Check whether the current iteration has timed out.
      cur_iter_timeout = iter_end - time.time()
      if data is None or cur_iter_timeout < 0:
        yield None
        iter_end = time.time() + iter_timeout
        continue
    else:
      assert data is not None, (
          'Iteration received no data despite no iter_timeout being set. '
          'cmd: %s' % cmd)

    # Construct lines to yield from raw data.
    buffer_output += data
    has_incomplete_line = buffer_output[-1] not in '\r\n'
    lines = buffer_output.splitlines()
    buffer_output = lines.pop() if has_incomplete_line else ''
    for line in lines:
      yield line
      if iter_timeout:
        iter_end = time.time() + iter_timeout

  if buffer_output:
    yield buffer_output
  if check_status and process.returncode:
    raise subprocess.CalledProcessError(process.returncode, cmd)
