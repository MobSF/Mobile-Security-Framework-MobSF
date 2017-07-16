# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A fake glob module implementation that uses fake_filesystem for unit tests.

Includes:
  FakeGlob: Uses a FakeFilesystem to provide a fake replacement for the
    glob module.

Usage:
>>> import fake_filesystem
>>> import fake_filesystem_glob
>>> filesystem = fake_filesystem.FakeFilesystem()
>>> glob_module = fake_filesystem_glob.FakeGlobModule(filesystem)

>>> file = filesystem.CreateFile('new-file')
>>> glob_module.glob('*')
['new-file']
>>> glob_module.glob('???-file')
['new-file']
"""

import fnmatch
import glob
import os

import fake_filesystem


class FakeGlobModule(object):
  """Uses a FakeFilesystem to provide a fake replacement for glob module."""

  def __init__(self, filesystem):
    """Construct fake glob module using the fake filesystem.

    Args:
      filesystem:  FakeFilesystem used to provide file system information
    """
    self._glob_module = glob
    self._os_module = fake_filesystem.FakeOsModule(filesystem)
    self._path_module = self._os_module.path

  def glob(self, pathname):  # pylint: disable-msg=C6409
    """Return a list of paths matching a pathname pattern.

    The pattern may contain shell-style wildcards a la fnmatch.

    Args:
      pathname: the pattern with which to find a list of paths

    Returns:
      List of strings matching the glob pattern.
    """
    if not self.has_magic(pathname):
      if self._path_module.exists(pathname):
        return [pathname]
      else:
        return []

    dirname, basename = self._path_module.split(pathname)

    if not dirname:
      return self.glob1(self._path_module.curdir, basename)
    elif self.has_magic(dirname):
      path_list = self.glob(dirname)
    else:
      path_list = [dirname]

    if not self.has_magic(basename):
      result = []
      for dirname in path_list:
        if basename or self._path_module.isdir(dirname):
          name = self._path_module.join(dirname, basename)
          if self._path_module.exists(name):
            result.append(name)
    else:
      result = []
      for dirname in path_list:
        sublist = self.glob1(dirname, basename)
        for name in sublist:
          result.append(self._path_module.join(dirname, name))

    return result

  def glob1(self, dirname, pattern):  # pylint: disable-msg=C6409
    if not dirname:
      dirname = self._path_module.curdir
    try:
      names = self._os_module.listdir(dirname)
    except os.error:
      return []
    if pattern[0] != '.':
      names = filter(lambda x: x[0] != '.', names)
    return fnmatch.filter(names, pattern)

  def __getattr__(self, name):
    """Forwards any non-faked calls to the standard glob module."""
    return getattr(self._glob_module, name)


def _RunDoctest():
  # pylint: disable-msg=C6111,C6204,W0406
  import doctest
  import fake_filesystem_glob
  return doctest.testmod(fake_filesystem_glob)


if __name__ == '__main__':
  _RunDoctest()
