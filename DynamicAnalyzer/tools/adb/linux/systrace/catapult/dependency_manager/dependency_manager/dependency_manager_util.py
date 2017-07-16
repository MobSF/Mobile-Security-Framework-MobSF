# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import stat
import sys
import zipfile

from dependency_manager import exceptions


def _WinReadOnlyHandler(func, path, execinfo):
  if not os.access(path, os.W_OK):
    os.chmod(path, stat.S_IWRITE)
    func(path)
  else:
    raise execinfo[0], execinfo[1], execinfo[2]


def RemoveDir(dir_path):
  assert os.path.isabs(dir_path)
  if sys.platform.startswith('win'):
    dir_path = u'\\\\?\\' + dir_path
  if os.path.isdir(dir_path):
    shutil.rmtree(dir_path, onerror=_WinReadOnlyHandler)


def VerifySafeArchive(archive):
  def ResolvePath(path_name):
    return os.path.realpath(os.path.abspath(path_name))
  # Must add pathsep to avoid false positives.
  # Ex: /tmp/abc/bad_file.py starts with /tmp/a but not /tmp/a/
  base_path = ResolvePath(os.getcwd()) + os.path.sep
  for member in archive.namelist():
    if not ResolvePath(os.path.join(base_path, member)).startswith(base_path):
      raise exceptions.ArchiveError(
          'Archive %s contains a bad member: %s.' % (archive.filename, member))


def GetModeFromPath(file_path):
  return stat.S_IMODE(os.stat(file_path).st_mode)


def GetModeFromZipInfo(zip_info):
  return zip_info.external_attr >> 16


def SetUnzippedDirPermissions(archive, unzipped_dir):
  """Set the file permissions in an unzipped archive.

     Designed to be called right after extractall() was called on |archive|.
     Noop on Win. Otherwise sets the executable bit on files where needed.

     Args:
         archive: A zipfile.ZipFile object opened for reading.
         unzipped_dir: A path to a directory containing the unzipped contents
             of |archive|.
  """
  if sys.platform.startswith('win'):
    # Windows doesn't have an executable bit, so don't mess with the ACLs.
    return
  for zip_info in archive.infolist():
    archive_acls = GetModeFromZipInfo(zip_info)
    if archive_acls & stat.S_IXUSR:
      # Only preserve owner execurable permissions.
      unzipped_path = os.path.abspath(
          os.path.join(unzipped_dir, zip_info.filename))
      mode = GetModeFromPath(unzipped_path)
      os.chmod(unzipped_path, mode | stat.S_IXUSR)


def UnzipArchive(archive_path, unzip_path):
  """Unzips a file if it is a zip file.

  Args:
      archive_path: The downloaded file to unzip.
      unzip_path: The destination directory to unzip to.

  Raises:
      ValueError: If |archive_path| is not a zipfile.
  """
  # TODO(aiolos): Add tests once the refactor is completed. crbug.com/551158
  if not (archive_path and zipfile.is_zipfile(archive_path)):
    raise ValueError(
        'Attempting to unzip a non-archive file at %s' % archive_path)
  if not os.path.exists(unzip_path):
    os.makedirs(unzip_path)
  try:
    with zipfile.ZipFile(archive_path, 'r') as archive:
      VerifySafeArchive(archive)
      assert os.path.isabs(unzip_path)
      unzip_path_without_prefix = unzip_path
      if sys.platform.startswith('win'):
        unzip_path = u'\\\\?\\' + unzip_path
      archive.extractall(path=unzip_path)
      SetUnzippedDirPermissions(archive, unzip_path)
  except:
    # Hack necessary because isdir doesn't work with escaped paths on Windows.
    if unzip_path_without_prefix and os.path.isdir(unzip_path_without_prefix):
      RemoveDir(unzip_path_without_prefix)
    raise
