# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import posixpath
import re

from devil import devil_env
from devil.android import device_errors
from devil.utils import cmd_helper

MD5SUM_DEVICE_LIB_PATH = '/data/local/tmp/md5sum'
MD5SUM_DEVICE_BIN_PATH = MD5SUM_DEVICE_LIB_PATH + '/md5sum_bin'

_STARTS_WITH_CHECKSUM_RE = re.compile(r'^\s*[0-9a-fA-F]{32}\s+')


def CalculateHostMd5Sums(paths):
  """Calculates the MD5 sum value for all items in |paths|.

  Directories are traversed recursively and the MD5 sum of each file found is
  reported in the result.

  Args:
    paths: A list of host paths to md5sum.
  Returns:
    A dict mapping file paths to their respective md5sum checksums.
  """
  if isinstance(paths, basestring):
    paths = [paths]

  md5sum_bin_host_path = devil_env.config.FetchPath('md5sum_host')
  if not os.path.exists(md5sum_bin_host_path):
    raise IOError('File not built: %s' % md5sum_bin_host_path)
  out = cmd_helper.GetCmdOutput(
    [md5sum_bin_host_path] + [os.path.realpath(p) for p in paths])

  return _ParseMd5SumOutput(out.splitlines())


def CalculateDeviceMd5Sums(paths, device):
  """Calculates the MD5 sum value for all items in |paths|.

  Directories are traversed recursively and the MD5 sum of each file found is
  reported in the result.

  Args:
    paths: A list of device paths to md5sum.
  Returns:
    A dict mapping file paths to their respective md5sum checksums.
  """
  if not paths:
    return {}

  if isinstance(paths, basestring):
    paths = [paths]
  # Allow generators
  paths = list(paths)

  md5sum_dist_path = devil_env.config.FetchPath('md5sum_device', device=device)

  if os.path.isdir(md5sum_dist_path):
    md5sum_dist_bin_path = os.path.join(md5sum_dist_path, 'md5sum_bin')
  else:
    md5sum_dist_bin_path = md5sum_dist_path

  if not os.path.exists(md5sum_dist_path):
    raise IOError('File not built: %s' % md5sum_dist_path)
  md5sum_file_size = os.path.getsize(md5sum_dist_bin_path)

  # For better performance, make the script as small as possible to try and
  # avoid needing to write to an intermediary file (which RunShellCommand will
  # do if necessary).
  md5sum_script = 'a=%s;' % MD5SUM_DEVICE_BIN_PATH
  # Check if the binary is missing or has changed (using its file size as an
  # indicator), and trigger a (re-)push via the exit code.
  md5sum_script += '! [[ $(ls -l $a) = *%d* ]]&&exit 2;' % md5sum_file_size
  # Make sure it can find libbase.so
  md5sum_script += 'export LD_LIBRARY_PATH=%s;' % MD5SUM_DEVICE_LIB_PATH
  if len(paths) > 1:
    prefix = posixpath.commonprefix(paths)
    if len(prefix) > 4:
      md5sum_script += 'p="%s";' % prefix
      paths = ['$p"%s"' % p[len(prefix):] for p in paths]

  md5sum_script += ';'.join('$a %s' % p for p in paths)
  # Don't fail the script if the last md5sum fails (due to file not found)
  # Note: ":" is equivalent to "true".
  md5sum_script += ';:'
  try:
    out = device.RunShellCommand(md5sum_script, shell=True, check_return=True)
  except device_errors.AdbShellCommandFailedError as e:
    # Push the binary only if it is found to not exist
    # (faster than checking up-front).
    if e.status == 2:
      # If files were previously pushed as root (adbd running as root), trying
      # to re-push as non-root causes the push command to report success, but
      # actually fail. So, wipe the directory first.
      device.RunShellCommand(['rm', '-rf', MD5SUM_DEVICE_LIB_PATH],
                             as_root=True, check_return=True)
      if os.path.isdir(md5sum_dist_path):
        device.adb.Push(md5sum_dist_path, MD5SUM_DEVICE_LIB_PATH)
      else:
        mkdir_cmd = 'a=%s;[[ -e $a ]] || mkdir $a' % MD5SUM_DEVICE_LIB_PATH
        device.RunShellCommand(mkdir_cmd, shell=True, check_return=True)
        device.adb.Push(md5sum_dist_bin_path, MD5SUM_DEVICE_BIN_PATH)

      out = device.RunShellCommand(md5sum_script, shell=True, check_return=True)
    else:
      raise

  return _ParseMd5SumOutput(out)


def _ParseMd5SumOutput(out):
  hash_and_path = (l.split(None, 1) for l in out
                   if l and _STARTS_WITH_CHECKSUM_RE.match(l))
  return dict((p, h) for h, p in hash_and_path)

