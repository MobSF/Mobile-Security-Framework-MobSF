# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import logging
import posixpath
import re

from devil.android.sdk import version_codes


logger = logging.getLogger(__name__)


_CMDLINE_DIR = '/data/local/tmp'
_CMDLINE_DIR_LEGACY = '/data/local'
_RE_NEEDS_QUOTING = re.compile(r'[^\w-]')  # Not in: alphanumeric or hyphens.
_QUOTES = '"\''  # Either a single or a double quote.
_ESCAPE = '\\'  # A backslash.


@contextlib.contextmanager
def CustomCommandLineFlags(device, cmdline_name, flags):
  """Context manager to change Chrome's command line temporarily.

  Example:

      with flag_changer.TemporaryCommandLineFlags(device, name, flags):
        # Launching Chrome will use the provided flags.

      # Previous set of flags on the device is now restored.

  Args:
    device: A DeviceUtils instance.
    cmdline_name: Name of the command line file where to store flags.
    flags: A sequence of command line flags to set.
  """
  # On Android N and above, we need to temporarily set SELinux to permissive
  # so that Chrome is allowed to read the command line file.
  # TODO(crbug.com/699082): Remove when a solution to avoid this is implemented.
  needs_permissive = (
      device.build_version_sdk >= version_codes.NOUGAT and
      device.GetEnforce())
  if needs_permissive:
    device.SetEnforce(enabled=False)
  try:
    changer = FlagChanger(device, cmdline_name)
    try:
      changer.ReplaceFlags(flags)
      yield
    finally:
      changer.Restore()
  finally:
    if needs_permissive:
      device.SetEnforce(enabled=True)


class FlagChanger(object):
  """Changes the flags Chrome runs with.

    Flags can be temporarily set for a particular set of unit tests.  These
    tests should call Restore() to revert the flags to their original state
    once the tests have completed.
  """

  def __init__(self, device, cmdline_file):
    """Initializes the FlagChanger and records the original arguments.

    Args:
      device: A DeviceUtils instance.
      cmdline_file: Name of the command line file where to store flags.
    """
    self._device = device

    if posixpath.sep in cmdline_file:
      raise ValueError(
          'cmdline_file should be a file name only, do not include path'
          ' separators in: %s' % cmdline_file)
    self._cmdline_path = posixpath.join(_CMDLINE_DIR, cmdline_file)

    cmdline_path_legacy = posixpath.join(_CMDLINE_DIR_LEGACY, cmdline_file)
    if self._device.PathExists(cmdline_path_legacy):
      logging.warning(
            'Removing legacy command line file %r.', cmdline_path_legacy)
      self._device.RemovePath(cmdline_path_legacy, as_root=True)

    self._state_stack = [None]  # Actual state is set by GetCurrentFlags().
    self.GetCurrentFlags()

  def GetCurrentFlags(self):
    """Read the current flags currently stored in the device.

    Also updates the internal state of the flag_changer.

    Returns:
      A list of flags.
    """
    if self._device.PathExists(self._cmdline_path):
      command_line = self._device.ReadFile(self._cmdline_path).strip()
    else:
      command_line = ''
    flags = _ParseFlags(command_line)

    # Store the flags as a set to facilitate adding and removing flags.
    self._state_stack[-1] = set(flags)
    return flags

  def ReplaceFlags(self, flags):
    """Replaces the flags in the command line with the ones provided.
       Saves the current flags state on the stack, so a call to Restore will
       change the state back to the one preceeding the call to ReplaceFlags.

    Args:
      flags: A sequence of command line flags to set, eg. ['--single-process'].
             Note: this should include flags only, not the name of a command
             to run (ie. there is no need to start the sequence with 'chrome').

    Returns:
      A list with the flags now stored on the device.
    """
    new_flags = set(flags)
    self._state_stack.append(new_flags)
    return self._UpdateCommandLineFile()

  def AddFlags(self, flags):
    """Appends flags to the command line if they aren't already there.
       Saves the current flags state on the stack, so a call to Restore will
       change the state back to the one preceeding the call to AddFlags.

    Args:
      flags: A sequence of flags to add on, eg. ['--single-process'].

    Returns:
      A list with the flags now stored on the device.
    """
    return self.PushFlags(add=flags)

  def RemoveFlags(self, flags):
    """Removes flags from the command line, if they exist.
       Saves the current flags state on the stack, so a call to Restore will
       change the state back to the one preceeding the call to RemoveFlags.

       Note that calling RemoveFlags after AddFlags will result in having
       two nested states.

    Args:
      flags: A sequence of flags to remove, eg. ['--single-process'].  Note
             that we expect a complete match when removing flags; if you want
             to remove a switch with a value, you must use the exact string
             used to add it in the first place.

    Returns:
      A list with the flags now stored on the device.
    """
    return self.PushFlags(remove=flags)

  def PushFlags(self, add=None, remove=None):
    """Appends and removes flags to/from the command line if they aren't already
       there. Saves the current flags state on the stack, so a call to Restore
       will change the state back to the one preceeding the call to PushFlags.

    Args:
      add: A list of flags to add on, eg. ['--single-process'].
      remove: A list of flags to remove, eg. ['--single-process'].  Note that we
              expect a complete match when removing flags; if you want to remove
              a switch with a value, you must use the exact string used to add
              it in the first place.

    Returns:
      A list with the flags now stored on the device.
    """
    new_flags = self._state_stack[-1].copy()
    if add:
      new_flags.update(add)
    if remove:
      new_flags.difference_update(remove)
    return self.ReplaceFlags(new_flags)

  def Restore(self):
    """Restores the flags to their state prior to the last AddFlags or
       RemoveFlags call.

    Returns:
      A list with the flags now stored on the device.
    """
    # The initial state must always remain on the stack.
    assert len(self._state_stack) > 1, (
      "Mismatch between calls to Add/RemoveFlags and Restore")
    self._state_stack.pop()
    return self._UpdateCommandLineFile()

  def _UpdateCommandLineFile(self):
    """Writes out the command line to the file, or removes it if empty.

    Returns:
      A list with the flags now stored on the device.
    """
    command_line = _SerializeFlags(self._state_stack[-1])
    if command_line is not None:
      self._device.WriteFile(self._cmdline_path, command_line)
    else:
      self._device.RemovePath(self._cmdline_path, force=True)

    current_flags = self.GetCurrentFlags()
    logger.info('Flags now set on the device: %s', current_flags)
    return current_flags


def _ParseFlags(line):
  """Parse the string containing the command line into a list of flags.

  It's a direct port of CommandLine.java::tokenizeQuotedArguments.

  The first token is assumed to be the (unused) program name and stripped off
  from the list of flags.

  Args:
    line: A string containing the entire command line.  The first token is
          assumed to be the program name.

  Returns:
     A list of flags, with quoting removed.
  """
  flags = []
  current_quote = None
  current_flag = None

  for c in line:
    # Detect start or end of quote block.
    if (current_quote is None and c in _QUOTES) or c == current_quote:
      if current_flag is not None and current_flag[-1] == _ESCAPE:
        # Last char was a backslash; pop it, and treat c as a literal.
        current_flag = current_flag[:-1] + c
      else:
        current_quote = c if current_quote is None else None
    elif current_quote is None and c.isspace():
      if current_flag is not None:
        flags.append(current_flag)
        current_flag = None
    else:
      if current_flag is None:
        current_flag = ''
      current_flag += c

  if current_flag is not None:
    if current_quote is not None:
      logger.warning('Unterminated quoted argument: ' + current_flag)
    flags.append(current_flag)

  # Return everything but the program name.
  return flags[1:]


def _SerializeFlags(flags):
  """Serialize a sequence of flags into a command line string.

  Args:
    flags: A sequence of strings with individual flags.

  Returns:
    A line with the command line contents to save; or None if the sequence of
    flags is empty.
  """
  if flags:
    # The first command line argument doesn't matter as we are not actually
    # launching the chrome executable using this command line.
    args = ['_']
    args.extend(_QuoteFlag(f) for f in flags)
    return ' '.join(args)
  else:
    return None


def _QuoteFlag(flag):
  """Validate and quote a single flag.

  Args:
    A string with the flag to quote.

  Returns:
    A string with the flag quoted so that it can be parsed by the algorithm
    in _ParseFlags; or None if the flag does not appear to be valid.
  """
  if '=' in flag:
    key, value = flag.split('=', 1)
  else:
    key, value = flag, None

  if not flag or _RE_NEEDS_QUOTING.search(key):
    # Probably not a valid flag, but quote the whole thing so it can be
    # parsed back correctly.
    return '"%s"' % flag.replace('"', r'\"')

  if value is None:
    return key

  if _RE_NEEDS_QUOTING.search(value):
    value = '"%s"' % value.replace('"', r'\"')
  return '='.join([key, value])
