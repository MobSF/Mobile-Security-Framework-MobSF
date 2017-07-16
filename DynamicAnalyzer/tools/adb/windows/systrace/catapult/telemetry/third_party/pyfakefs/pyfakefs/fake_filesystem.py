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
#
# pylint: disable-msg=W0612,W0613,C6409

"""A fake filesystem implementation for unit testing.

Includes:
  FakeFile:  Provides the appearance of a real file.
  FakeDirectory: Provides the appearance of a real dir.
  FakeFilesystem:  Provides the appearance of a real directory hierarchy.
  FakeOsModule:  Uses FakeFilesystem to provide a fake os module replacement.
  FakePathModule:  Faked os.path module replacement.
  FakeFileOpen:  Faked file() and open() function replacements.

Usage:
>>> import fake_filesystem
>>> filesystem = fake_filesystem.FakeFilesystem()
>>> os_module = fake_filesystem.FakeOsModule(filesystem)
>>> pathname = '/a/new/dir/new-file'

Create a new file object, creating parent directory objects as needed:
>>> os_module.path.exists(pathname)
False
>>> new_file = filesystem.CreateFile(pathname)

File objects can't be overwritten:
>>> os_module.path.exists(pathname)
True
>>> try:
...   filesystem.CreateFile(pathname)
... except IOError as e:
...   assert e.errno == errno.EEXIST, 'unexpected errno: %d' % e.errno
...   assert e.strerror == 'File already exists in fake filesystem'

Remove a file object:
>>> filesystem.RemoveObject(pathname)
>>> os_module.path.exists(pathname)
False

Create a new file object at the previous path:
>>> beatles_file = filesystem.CreateFile(pathname,
...     contents='Dear Prudence\\nWon\\'t you come out to play?\\n')
>>> os_module.path.exists(pathname)
True

Use the FakeFileOpen class to read fake file objects:
>>> file_module = fake_filesystem.FakeFileOpen(filesystem)
>>> for line in file_module(pathname):
...     print line.rstrip()
...
Dear Prudence
Won't you come out to play?

File objects cannot be treated like directory objects:
>>> os_module.listdir(pathname)  #doctest: +NORMALIZE_WHITESPACE
Traceback (most recent call last):
  File "fake_filesystem.py", line 291, in listdir
    raise OSError(errno.ENOTDIR,
OSError: [Errno 20] Fake os module: not a directory: '/a/new/dir/new-file'

The FakeOsModule can list fake directory objects:
>>> os_module.listdir(os_module.path.dirname(pathname))
['new-file']

The FakeOsModule also supports stat operations:
>>> import stat
>>> stat.S_ISREG(os_module.stat(pathname).st_mode)
True
>>> stat.S_ISDIR(os_module.stat(os_module.path.dirname(pathname)).st_mode)
True
"""

import errno
import heapq
import os
import stat
import sys
import time
import warnings
try:
  import cStringIO as io  # pylint: disable-msg=C6204
except ImportError:
  import io  # pylint: disable-msg=C6204

__pychecker__ = 'no-reimportself'

__version__ = '2.5'

PERM_READ = 0o400      # Read permission bit.
PERM_WRITE = 0o200     # Write permission bit.
PERM_EXE = 0o100       # Write permission bit.
PERM_DEF = 0o777       # Default permission bits.
PERM_DEF_FILE = 0o666  # Default permission bits (regular file)
PERM_ALL = 0o7777      # All permission bits.

_OPEN_MODE_MAP = {
    # mode name:(file must exist, need read, need write,
    #            truncate [implies need write], append)
    'r': (True, True, False, False, False),
    'w': (False, False, True, True, False),
    'a': (False, False, True, False, True),
    'r+': (True, True, True, False, False),
    'w+': (False, True, True, True, False),
    'a+': (False, True, True, False, True),
    }

_MAX_LINK_DEPTH = 20

FAKE_PATH_MODULE_DEPRECATION = ('Do not instantiate a FakePathModule directly; '
                                'let FakeOsModule instantiate it.  See the '
                                'FakeOsModule docstring for details.')


class Error(Exception):
  pass

_is_windows = sys.platform.startswith('win')
_is_cygwin = sys.platform == 'cygwin'

if _is_windows:
  # On Windows, raise WindowsError instead of OSError if available
  OSError = WindowsError  # pylint: disable-msg=E0602,W0622


class FakeLargeFileIoException(Error):
  def __init__(self, file_path):
    Error.__init__(self,
                   'Read and write operations not supported for '
                   'fake large file: %s' % file_path)


def CopyModule(old):
  """Recompiles and creates new module object."""
  saved = sys.modules.pop(old.__name__, None)
  new = __import__(old.__name__)
  sys.modules[old.__name__] = saved
  return new


class FakeFile(object):
  """Provides the appearance of a real file.

     Attributes currently faked out:
       st_mode: user-specified, otherwise S_IFREG
       st_ctime: the time.time() timestamp when the file is created.
       st_size: the size of the file

     Other attributes needed by os.stat are assigned default value of None
      these include: st_ino, st_dev, st_nlink, st_uid, st_gid, st_atime,
      st_mtime
  """

  def __init__(self, name, st_mode=stat.S_IFREG | PERM_DEF_FILE,
               contents=None):
    """init.

    Args:
      name:  name of the file/directory, without parent path information
      st_mode:  the stat.S_IF* constant representing the file type (i.e.
        stat.S_IFREG, stat.SIFDIR)
      contents:  the contents of the filesystem object; should be a string for
        regular files, and a list of other FakeFile or FakeDirectory objects
        for FakeDirectory objects
    """
    self.name = name
    self.st_mode = st_mode
    self.contents = contents
    self.epoch = 0
    self.st_ctime = int(time.time())
    self.st_atime = self.st_ctime
    self.st_mtime = self.st_ctime
    if contents:
      self.st_size = len(contents)
    else:
      self.st_size = 0
    # Non faked features, write setter methods for fakeing them
    self.st_ino = None
    self.st_dev = None
    self.st_nlink = None
    self.st_uid = None
    self.st_gid = None

  def SetLargeFileSize(self, st_size):
    """Sets the self.st_size attribute and replaces self.content with None.

    Provided specifically to simulate very large files without regards
    to their content (which wouldn't fit in memory)

    Args:
      st_size: The desired file size

    Raises:
      IOError: if the st_size is not a non-negative integer
    """
    # the st_size should be an positive integer value
    if not isinstance(st_size, int) or st_size < 0:
      raise IOError(errno.ENOSPC,
                    'Fake file object: can not create non negative integer '
                    'size=%r fake file' % st_size,
                    self.name)

    self.st_size = st_size
    self.contents = None

  def IsLargeFile(self):
    """Return True if this file was initialized with size but no contents."""
    return self.contents is None

  def SetContents(self, contents):
    """Sets the file contents and size.

    Args:
      contents: string, new content of file.
    """
    # convert a byte array to a string
    if sys.version_info >= (3, 0) and isinstance(contents, bytes):
      contents = ''.join(chr(i) for i in contents)
    self.contents = contents
    self.st_size = len(contents)
    self.epoch += 1

  def SetSize(self, st_size):
    """Resizes file content, padding with nulls if new size exceeds the old.

    Args:
      st_size: The desired size for the file.

    Raises:
      IOError: if the st_size arg is not a non-negative integer
    """

    if not isinstance(st_size, int) or st_size < 0:
      raise IOError(errno.ENOSPC,
                    'Fake file object: can not create non negative integer '
                    'size=%r fake file' % st_size,
                    self.name)

    current_size = len(self.contents)
    if st_size < current_size:
      self.contents = self.contents[:st_size]
    else:
      self.contents = '%s%s' % (self.contents, '\0' * (st_size - current_size))
    self.st_size = len(self.contents)
    self.epoch += 1

  def SetATime(self, st_atime):
    """Set the self.st_atime attribute.

    Args:
      st_atime: The desired atime.
    """
    self.st_atime = st_atime

  def SetMTime(self, st_mtime):
    """Set the self.st_mtime attribute.

    Args:
      st_mtime: The desired mtime.
    """
    self.st_mtime = st_mtime

  def __str__(self):
    return '%s(%o)' % (self.name, self.st_mode)

  def SetIno(self, st_ino):
    """Set the self.st_ino attribute.

    Args:
      st_ino: The desired inode.
    """
    self.st_ino = st_ino


class FakeDirectory(FakeFile):
  """Provides the appearance of a real dir."""

  def __init__(self, name, perm_bits=PERM_DEF):
    """init.

    Args:
      name:  name of the file/directory, without parent path information
      perm_bits: permission bits. defaults to 0o777.
    """
    FakeFile.__init__(self, name, stat.S_IFDIR | perm_bits, {})

  def AddEntry(self, pathname):
    """Adds a child FakeFile to this directory.

    Args:
      pathname:  FakeFile instance to add as a child of this directory
    """
    self.contents[pathname.name] = pathname

  def GetEntry(self, pathname_name):
    """Retrieves the specified child file or directory.

    Args:
      pathname_name: basename of the child object to retrieve
    Returns:
      string, file contents
    Raises:
      KeyError: if no child exists by the specified name
    """
    return self.contents[pathname_name]

  def RemoveEntry(self, pathname_name):
    """Removes the specified child file or directory.

    Args:
      pathname_name: basename of the child object to remove

    Raises:
      KeyError: if no child exists by the specified name
    """
    del self.contents[pathname_name]

  def __str__(self):
    rc = super(FakeDirectory, self).__str__() + ':\n'
    for item in self.contents:
      item_desc = self.contents[item].__str__()
      for line in item_desc.split('\n'):
        if line:
          rc = rc + '  ' + line + '\n'
    return rc


class FakeFilesystem(object):
  """Provides the appearance of a real directory tree for unit testing."""

  def __init__(self, path_separator=os.path.sep):
    """init.

    Args:
      path_separator:  optional substitute for os.path.sep
    """
    self.path_separator = path_separator
    self.root = FakeDirectory(self.path_separator)
    self.cwd = self.root.name
    # We can't query the current value without changing it:
    self.umask = os.umask(0o22)
    os.umask(self.umask)
    # A list of open file objects. Their position in the list is their
    # file descriptor number
    self.open_files = []
    # A heap containing all free positions in self.open_files list
    self.free_fd_heap = []

  def SetIno(self, path, st_ino):
    """Set the self.st_ino attribute of file at 'path'.

    Args:
      path: Path to file.
      st_ino: The desired inode.
    """
    self.GetObject(path).SetIno(st_ino)

  def AddOpenFile(self, file_obj):
    """Adds file_obj to the list of open files on the filesystem.

    The position in the self.open_files array is the file descriptor number

    Args:
      file_obj:  file object to be added to open files list.

    Returns:
      File descriptor number for the file object.
    """
    if self.free_fd_heap:
      open_fd = heapq.heappop(self.free_fd_heap)
      self.open_files[open_fd] = file_obj
      return open_fd

    self.open_files.append(file_obj)
    return len(self.open_files) - 1

  def CloseOpenFile(self, file_obj):
    """Removes file_obj from the list of open files on the filesystem.

    Sets the entry in open_files to None.

    Args:
      file_obj:  file object to be removed to open files list.
    """
    self.open_files[file_obj.filedes] = None
    heapq.heappush(self.free_fd_heap, file_obj.filedes)

  def GetOpenFile(self, file_des):
    """Returns an open file.

    Args:
      file_des:  file descriptor of the open file.

    Raises:
      OSError: an invalid file descriptor.
      TypeError: filedes is not an integer.

    Returns:
      Open file object.
    """
    if not isinstance(file_des, int):
      raise TypeError('an integer is required')
    if (file_des >= len(self.open_files) or
        self.open_files[file_des] is None):
      raise OSError(errno.EBADF, 'Bad file descriptor', file_des)
    return self.open_files[file_des]

  def CollapsePath(self, path):
    """Mimics os.path.normpath using the specified path_separator.

    Mimics os.path.normpath using the path_separator that was specified
    for this FakeFilesystem.  Normalizes the path, but unlike the method
    NormalizePath, does not make it absolute.  Eliminates dot components
    (. and ..) and combines repeated path separators (//).  Initial ..
    components are left in place for relative paths.  If the result is an empty
    path, '.' is returned instead.  Unlike the real os.path.normpath, this does
    not replace '/' with '\\' on Windows.

    Args:
      path:  (str) The path to normalize.

    Returns:
      (str) A copy of path with empty components and dot components removed.
    """
    is_absolute_path = path.startswith(self.path_separator)
    path_components = path.split(self.path_separator)
    collapsed_path_components = []
    for component in path_components:
      if (not component) or (component == '.'):
        continue
      if component == '..':
        if collapsed_path_components and (
            collapsed_path_components[-1] != '..'):
          # Remove an up-reference: directory/..
          collapsed_path_components.pop()
          continue
        elif is_absolute_path:
          # Ignore leading .. components if starting from the root directory.
          continue
      collapsed_path_components.append(component)
    collapsed_path = self.path_separator.join(collapsed_path_components)
    if is_absolute_path:
      collapsed_path = self.path_separator + collapsed_path
    return collapsed_path or '.'

  def NormalizePath(self, path):
    """Absolutize and minimalize the given path.

    Forces all relative paths to be absolute, and normalizes the path to
    eliminate dot and empty components.

    Args:
      path:  path to normalize

    Returns:
      The normalized path relative to the current working directory, or the root
        directory if path is empty.
    """
    if not path:
      path = self.path_separator
    elif not path.startswith(self.path_separator):
      # Prefix relative paths with cwd, if cwd is not root.
      path = self.path_separator.join(
          (self.cwd != self.root.name and self.cwd or '',
           path))
    if path == '.':
      path = self.cwd
    return self.CollapsePath(path)

  def SplitPath(self, path):
    """Mimics os.path.split using the specified path_separator.

    Mimics os.path.split using the path_separator that was specified
    for this FakeFilesystem.

    Args:
      path:  (str) The path to split.

    Returns:
      (str) A duple (pathname, basename) for which pathname does not
          end with a slash, and basename does not contain a slash.
    """
    path_components = path.split(self.path_separator)
    if not path_components:
      return ('', '')
    basename = path_components.pop()
    if not path_components:
      return ('', basename)
    for component in path_components:
      if component:
        # The path is not the root; it contains a non-separator component.
        # Strip all trailing separators.
        while not path_components[-1]:
          path_components.pop()
        return (self.path_separator.join(path_components), basename)
    # Root path.  Collapse all leading separators.
    return (self.path_separator, basename)

  def JoinPaths(self, *paths):
    """Mimics os.path.join using the specified path_separator.

    Mimics os.path.join using the path_separator that was specified
    for this FakeFilesystem.

    Args:
      *paths:  (str) Zero or more paths to join.

    Returns:
      (str) The paths joined by the path separator, starting with the last
          absolute path in paths.
    """
    if len(paths) == 1:
      return paths[0]
    joined_path_segments = []
    for path_segment in paths:
      if path_segment.startswith(self.path_separator):
        # An absolute path
        joined_path_segments = [path_segment]
      else:
        if (joined_path_segments and
            not joined_path_segments[-1].endswith(self.path_separator)):
          joined_path_segments.append(self.path_separator)
        if path_segment:
          joined_path_segments.append(path_segment)
    return ''.join(joined_path_segments)

  def GetPathComponents(self, path):
    """Breaks the path into a list of component names.

    Does not include the root directory as a component, as all paths
    are considered relative to the root directory for the FakeFilesystem.
    Callers should basically follow this pattern:

      file_path = self.NormalizePath(file_path)
      path_components = self.GetPathComponents(file_path)
      current_dir = self.root
      for component in path_components:
        if component not in current_dir.contents:
          raise IOError
        DoStuffWithComponent(curent_dir, component)
        current_dir = current_dir.GetEntry(component)

    Args:
      path:  path to tokenize

    Returns:
      The list of names split from path
    """
    if not path or path == self.root.name:
      return []
    path_components = path.split(self.path_separator)
    assert path_components
    if not path_components[0]:
      # This is an absolute path.
      path_components = path_components[1:]
    return path_components

  def Exists(self, file_path):
    """True if a path points to an existing file system object.

    Args:
      file_path:  path to examine

    Returns:
      bool(if object exists)

    Raises:
      TypeError: if file_path is None
    """
    if file_path is None:
      raise TypeError
    if not file_path:
      return False
    try:
      file_path = self.ResolvePath(file_path)
    except IOError:
      return False
    if file_path == self.root.name:
      return True
    path_components = self.GetPathComponents(file_path)
    current_dir = self.root
    for component in path_components:
      if component not in current_dir.contents:
        return False
      current_dir = current_dir.contents[component]
    return True

  def ResolvePath(self, file_path):
    """Follow a path, resolving symlinks.

    ResolvePath traverses the filesystem along the specified file path,
    resolving file names and symbolic links until all elements of the path are
    exhausted, or we reach a file which does not exist.  If all the elements
    are not consumed, they just get appended to the path resolved so far.
    This gives us the path which is as resolved as it can be, even if the file
    does not exist.

    This behavior mimics Unix semantics, and is best shown by example.  Given a
    file system that looks like this:

          /a/b/
          /a/b/c -> /a/b2          c is a symlink to /a/b2
          /a/b2/x
          /a/c   -> ../d
          /a/x   -> y
     Then:
          /a/b/x      =>  /a/b/x
          /a/c        =>  /a/d
          /a/x        =>  /a/y
          /a/b/c/d/e  =>  /a/b2/d/e

    Args:
      file_path:  path to examine

    Returns:
      resolved_path (string) or None

    Raises:
      TypeError: if file_path is None
      IOError: if file_path is '' or a part of the path doesn't exist
    """

    def _ComponentsToPath(component_folders):
      return '%s%s' % (self.path_separator,
                       self.path_separator.join(component_folders))

    def _ValidRelativePath(file_path):
      while file_path and '/..' in file_path:
        file_path = file_path[:file_path.rfind('/..')]
        if not self.Exists(self.NormalizePath(file_path)):
          return False
      return True

    def _FollowLink(link_path_components, link):
      """Follow a link w.r.t. a path resolved so far.

      The component is either a real file, which is a no-op, or a symlink.
      In the case of a symlink, we have to modify the path as built up so far
        /a/b => ../c   should yield /a/../c (which will normalize to /a/c)
        /a/b => x      should yield /a/x
        /a/b => /x/y/z should yield /x/y/z
      The modified path may land us in a new spot which is itself a
      link, so we may repeat the process.

      Args:
        link_path_components: The resolved path built up to the link so far.
        link: The link object itself.

      Returns:
        (string) the updated path resolved after following the link.

      Raises:
        IOError: if there are too many levels of symbolic link
      """
      link_path = link.contents
      # For links to absolute paths, we want to throw out everything in the
      # path built so far and replace with the link.  For relative links, we
      # have to append the link to what we have so far,
      if not link_path.startswith(self.path_separator):
        # Relative path.  Append remainder of path to what we have processed
        # so far, excluding the name of the link itself.
        # /a/b => ../c   should yield /a/../c (which will normalize to /c)
        # /a/b => d should yield a/d
        components = link_path_components[:-1]
        components.append(link_path)
        link_path = self.path_separator.join(components)
      # Don't call self.NormalizePath(), as we don't want to prepend self.cwd.
      return self.CollapsePath(link_path)

    if file_path is None:
      # file.open(None) raises TypeError, so mimic that.
      raise TypeError('Expected file system path string, received None')
    if not file_path or not _ValidRelativePath(file_path):
      # file.open('') raises IOError, so mimic that, and validate that all
      # parts of a relative path exist.
      raise IOError(errno.ENOENT,
                    'No such file or directory: \'%s\'' % file_path)
    file_path = self.NormalizePath(file_path)
    if file_path == self.root.name:
      return file_path

    current_dir = self.root
    path_components = self.GetPathComponents(file_path)

    resolved_components = []
    link_depth = 0
    while path_components:
      component = path_components.pop(0)
      resolved_components.append(component)
      if component not in current_dir.contents:
        # The component of the path at this point does not actually exist in
        # the folder.   We can't resolve the path any more.  It is legal to link
        # to a file that does not yet exist, so rather than raise an error, we
        # just append the remaining components to what return path we have built
        # so far and return that.
        resolved_components.extend(path_components)
        break
      current_dir = current_dir.contents[component]

      # Resolve any possible symlinks in the current path component.
      if stat.S_ISLNK(current_dir.st_mode):
        # This link_depth check is not really meant to be an accurate check.
        # It is just a quick hack to prevent us from looping forever on
        # cycles.
        link_depth += 1
        if link_depth > _MAX_LINK_DEPTH:
          raise IOError(errno.EMLINK,
                        'Too many levels of symbolic links: \'%s\'' %
                        _ComponentsToPath(resolved_components))
        link_path = _FollowLink(resolved_components, current_dir)

        # Following the link might result in the complete replacement of the
        # current_dir, so we evaluate the entire resulting path.
        target_components = self.GetPathComponents(link_path)
        path_components = target_components + path_components
        resolved_components = []
        current_dir = self.root
    return _ComponentsToPath(resolved_components)

  def GetObjectFromNormalizedPath(self, file_path):
    """Searches for the specified filesystem object within the fake filesystem.

    Args:
      file_path: specifies target FakeFile object to retrieve, with a
          path that has already been normalized/resolved

    Returns:
      the FakeFile object corresponding to file_path

    Raises:
      IOError: if the object is not found
    """
    if file_path == self.root.name:
      return self.root
    path_components = self.GetPathComponents(file_path)
    target_object = self.root
    try:
      for component in path_components:
        if not isinstance(target_object, FakeDirectory):
          raise IOError(errno.ENOENT,
                        'No such file or directory in fake filesystem',
                        file_path)
        target_object = target_object.GetEntry(component)
    except KeyError:
      raise IOError(errno.ENOENT,
                    'No such file or directory in fake filesystem',
                    file_path)
    return target_object

  def GetObject(self, file_path):
    """Searches for the specified filesystem object within the fake filesystem.

    Args:
      file_path: specifies target FakeFile object to retrieve

    Returns:
      the FakeFile object corresponding to file_path

    Raises:
      IOError: if the object is not found
    """
    file_path = self.NormalizePath(file_path)
    return self.GetObjectFromNormalizedPath(file_path)

  def ResolveObject(self, file_path):
    """Searches for the specified filesystem object, resolving all links.

    Args:
      file_path: specifies target FakeFile object to retrieve

    Returns:
      the FakeFile object corresponding to file_path

    Raises:
      IOError: if the object is not found
    """
    return self.GetObjectFromNormalizedPath(self.ResolvePath(file_path))

  def LResolveObject(self, path):
    """Searches for the specified object, resolving only parent links.

    This is analogous to the stat/lstat difference.  This resolves links *to*
    the object but not of the final object itself.

    Args:
      path: specifies target FakeFile object to retrieve

    Returns:
      the FakeFile object corresponding to path

    Raises:
      IOError: if the object is not found
    """
    if path == self.root.name:
      # The root directory will never be a link
      return self.root
    parent_directory, child_name = self.SplitPath(path)
    if not parent_directory:
      parent_directory = self.cwd
    try:
      parent_obj = self.ResolveObject(parent_directory)
      assert parent_obj
      if not isinstance(parent_obj, FakeDirectory):
        raise IOError(errno.ENOENT,
                      'No such file or directory in fake filesystem',
                      path)
      return parent_obj.GetEntry(child_name)
    except KeyError:
      raise IOError(errno.ENOENT,
                    'No such file or directory in the fake filesystem',
                    path)

  def AddObject(self, file_path, file_object):
    """Add a fake file or directory into the filesystem at file_path.

    Args:
      file_path: the path to the file to be added relative to self
      file_object: file or directory to add

    Raises:
      IOError: if file_path does not correspond to a directory
    """
    try:
      target_directory = self.GetObject(file_path)
      target_directory.AddEntry(file_object)
    except AttributeError:
      raise IOError(errno.ENOTDIR,
                    'Not a directory in the fake filesystem',
                    file_path)

  def RemoveObject(self, file_path):
    """Remove an existing file or directory.

    Args:
      file_path: the path to the file relative to self

    Raises:
      IOError: if file_path does not correspond to an existing file, or if part
        of the path refers to something other than a directory
      OSError: if the directory is in use (eg, if it is '/')
    """
    if file_path == self.root.name:
      raise OSError(errno.EBUSY, 'Fake device or resource busy',
                    file_path)
    try:
      dirname, basename = self.SplitPath(file_path)
      target_directory = self.GetObject(dirname)
      target_directory.RemoveEntry(basename)
    except KeyError:
      raise IOError(errno.ENOENT,
                    'No such file or directory in the fake filesystem',
                    file_path)
    except AttributeError:
      raise IOError(errno.ENOTDIR,
                    'Not a directory in the fake filesystem',
                    file_path)

  def CreateDirectory(self, directory_path, perm_bits=PERM_DEF, inode=None):
    """Creates directory_path, and all the parent directories.

    Helper method to set up your test faster

    Args:
      directory_path:  directory to create
      perm_bits: permission bits
      inode: inode of directory

    Returns:
      the newly created FakeDirectory object

    Raises:
      OSError:  if the directory already exists
    """
    directory_path = self.NormalizePath(directory_path)
    if self.Exists(directory_path):
      raise OSError(errno.EEXIST,
                    'Directory exists in fake filesystem',
                    directory_path)
    path_components = self.GetPathComponents(directory_path)
    current_dir = self.root

    for component in path_components:
      if component not in current_dir.contents:
        new_dir = FakeDirectory(component, perm_bits)
        current_dir.AddEntry(new_dir)
        current_dir = new_dir
      else:
        current_dir = current_dir.contents[component]

    current_dir.SetIno(inode)
    return current_dir

  def CreateFile(self, file_path, st_mode=stat.S_IFREG | PERM_DEF_FILE,
                 contents='', st_size=None, create_missing_dirs=True,
                 apply_umask=False, inode=None):
    """Creates file_path, including all the parent directories along the way.

    Helper method to set up your test faster.

    Args:
      file_path: path to the file to create
      st_mode: the stat.S_IF constant representing the file type
      contents: the contents of the file
      st_size: file size; only valid if contents=None
      create_missing_dirs: if True, auto create missing directories
      apply_umask: whether or not the current umask must be applied on st_mode
      inode: inode of the file

    Returns:
      the newly created FakeFile object

    Raises:
      IOError: if the file already exists
      IOError: if the containing directory is required and missing
    """
    file_path = self.NormalizePath(file_path)
    if self.Exists(file_path):
      raise IOError(errno.EEXIST,
                    'File already exists in fake filesystem',
                    file_path)
    parent_directory, new_file = self.SplitPath(file_path)
    if not parent_directory:
      parent_directory = self.cwd
    if not self.Exists(parent_directory):
      if not create_missing_dirs:
        raise IOError(errno.ENOENT, 'No such fake directory', parent_directory)
      self.CreateDirectory(parent_directory)
    if apply_umask:
      st_mode &= ~self.umask
    file_object = FakeFile(new_file, st_mode, contents)
    file_object.SetIno(inode)
    self.AddObject(parent_directory, file_object)

    # set the size if st_size is given
    if not contents and st_size is not None:
      try:
        file_object.SetLargeFileSize(st_size)
      except IOError:
        self.RemoveObject(file_path)
        raise

    return file_object

  def CreateLink(self, file_path, link_target):
    """Creates the specified symlink, pointed at the specified link target.

    Args:
      file_path:  path to the symlink to create
      link_target:  the target of the symlink

    Returns:
      the newly created FakeFile object

    Raises:
      IOError:  if the file already exists
    """
    resolved_file_path = self.ResolvePath(file_path)
    return self.CreateFile(resolved_file_path, st_mode=stat.S_IFLNK | PERM_DEF,
                           contents=link_target)

  def __str__(self):
    return str(self.root)


class FakePathModule(object):
  """Faked os.path module replacement.

  FakePathModule should *only* be instantiated by FakeOsModule.  See the
  FakeOsModule docstring for details.
  """
  _OS_PATH_COPY = CopyModule(os.path)

  def __init__(self, filesystem, os_module=None):
    """Init.

    Args:
      filesystem:  FakeFilesystem used to provide file system information
      os_module: (deprecated) FakeOsModule to assign to self.os
    """
    self.filesystem = filesystem
    self._os_path = self._OS_PATH_COPY
    if os_module is None:
      warnings.warn(FAKE_PATH_MODULE_DEPRECATION, DeprecationWarning,
                    stacklevel=2)
    self._os_path.os = self.os = os_module
    self.sep = self.filesystem.path_separator

  def exists(self, path):
    """Determines whether the file object exists within the fake filesystem.

    Args:
      path:  path to the file object

    Returns:
      bool (if file exists)
    """
    return self.filesystem.Exists(path)

  def lexists(self, path):
    """Test whether a path exists.  Returns True for broken symbolic links.

    Args:
      path:  path to the symlnk object

    Returns:
      bool (if file exists)
    """
    return self.exists(path) or self.islink(path)

  def getsize(self, path):
    """Return the file object size in bytes.

    Args:
      path:  path to the file object

    Returns:
      file size in bytes
    """
    file_obj = self.filesystem.GetObject(path)
    return file_obj.st_size

  def _istype(self, path, st_flag):
    """Helper function to implement isdir(), islink(), etc.

    See the stat(2) man page for valid stat.S_I* flag values

    Args:
      path:  path to file to stat and test
      st_flag:  the stat.S_I* flag checked for the file's st_mode

    Returns:
      boolean (the st_flag is set in path's st_mode)

    Raises:
      TypeError: if path is None
    """
    if path is None:
      raise TypeError
    try:
      obj = self.filesystem.ResolveObject(path)
      if obj:
        return stat.S_IFMT(obj.st_mode) == st_flag
    except IOError:
      return False
    return False

  def isabs(self, path):
    if self.filesystem.path_separator == os.path.sep:
      # Pass through to os.path.isabs, which on Windows has special
      # handling for a leading drive letter.
      return self._os_path.isabs(path)
    else:
      return path.startswith(self.filesystem.path_separator)

  def isdir(self, path):
    """Determines if path identifies a directory."""
    return self._istype(path, stat.S_IFDIR)

  def isfile(self, path):
    """Determines if path identifies a regular file."""
    return self._istype(path, stat.S_IFREG)

  def islink(self, path):
    """Determines if path identifies a symbolic link.

    Args:
      path: path to filesystem object.

    Returns:
      boolean (the st_flag is set in path's st_mode)

    Raises:
      TypeError: if path is None
    """
    if path is None:
      raise TypeError
    try:
      link_obj = self.filesystem.LResolveObject(path)
      return stat.S_IFMT(link_obj.st_mode) == stat.S_IFLNK
    except IOError:
      return False
    except KeyError:
      return False
    return False

  def getmtime(self, path):
    """Returns the mtime of the file."""
    try:
      file_obj = self.filesystem.GetObject(path)
    except IOError as e:
      raise OSError(errno.ENOENT, str(e))
    return file_obj.st_mtime

  def abspath(self, path):
    """Return the absolute version of a path."""
    if not self.isabs(path):
      if sys.version_info < (3, 0) and isinstance(path, unicode):
        cwd = self.os.getcwdu()
      else:
        cwd = self.os.getcwd()
      path = self.join(cwd, path)
    return self.normpath(path)

  def join(self, *p):
    """Returns the completed path with a separator of the parts."""
    return self.filesystem.JoinPaths(*p)

  def normpath(self, path):
    """Normalize path, eliminating double slashes, etc."""
    return self.filesystem.CollapsePath(path)

  if _is_windows:

    def relpath(self, path, start=None):
      """ntpath.relpath() needs the cwd passed in the start argument."""
      if start is None:
        start = self.filesystem.cwd
      path = self._os_path.relpath(path, start)
      return path.replace(self._os_path.sep, self.filesystem.path_separator)

    realpath = abspath

  def __getattr__(self, name):
    """Forwards any non-faked calls to os.path."""
    return self._os_path.__dict__[name]


class FakeOsModule(object):
  """Uses FakeFilesystem to provide a fake os module replacement.

  Do not create os.path separately from os, as there is a necessary circular
  dependency between os and os.path to replicate the behavior of the standard
  Python modules.  What you want to do is to just let FakeOsModule take care of
  os.path setup itself.

  # You always want to do this.
  filesystem = fake_filesystem.FakeFilesystem()
  my_os_module = fake_filesystem.FakeOsModule(filesystem)
  """

  def __init__(self, filesystem, os_path_module=None):
    """Also exposes self.path (to fake os.path).

    Args:
      filesystem:  FakeFilesystem used to provide file system information
      os_path_module: (deprecated) optional FakePathModule instance
    """
    self.filesystem = filesystem
    self.sep = filesystem.path_separator
    self._os_module = os
    if os_path_module is None:
      self.path = FakePathModule(self.filesystem, self)
    else:
      warnings.warn(FAKE_PATH_MODULE_DEPRECATION, DeprecationWarning,
                    stacklevel=2)
      self.path = os_path_module
    if sys.version_info < (3, 0):
      self.fdopen = self._fdopen_ver2
    else:
      self.fdopen = self._fdopen

  def _fdopen(self, *args, **kwargs):
    """Redirector to open() builtin function.

    Args:
      *args: pass through args
      **kwargs: pass through kwargs

    Returns:
      File object corresponding to file_des.

    Raises:
      TypeError: if file descriptor is not an integer.
    """
    if not isinstance(args[0], int):
      raise TypeError('an integer is required')
    return FakeFileOpen(self.filesystem)(*args, **kwargs)

  def _fdopen_ver2(self, file_des, mode='r', bufsize=None):
    """Returns an open file object connected to the file descriptor file_des.

    Args:
      file_des: An integer file descriptor for the file object requested.
      mode: additional file flags. Currently checks to see if the mode matches
        the mode of the requested file object.
      bufsize: ignored. (Used for signature compliance with __builtin__.fdopen)

    Returns:
      File object corresponding to file_des.

    Raises:
      OSError: if bad file descriptor or incompatible mode is given.
      TypeError: if file descriptor is not an integer.
    """
    if not isinstance(file_des, int):
      raise TypeError('an integer is required')

    try:
      return FakeFileOpen(self.filesystem).Call(file_des, mode=mode)
    except IOError as e:
      raise OSError(e)

  def open(self, file_path, flags, mode=None):
    """Returns the file descriptor for a FakeFile.

    WARNING: This implementation only implements creating a file. Please fill
    out the remainder for your needs.

    Args:
      file_path: the path to the file
      flags: low-level bits to indicate io operation
      mode: bits to define default permissions

    Returns:
      A file descriptor.

    Raises:
      OSError: if the path cannot be found
      ValueError: if invalid mode is given
      NotImplementedError: if an unsupported flag is passed in
    """
    if flags & os.O_CREAT:
      fake_file = FakeFileOpen(self.filesystem)(file_path, 'w')
      if mode:
        self.chmod(file_path, mode)
      return fake_file.fileno()
    else:
      raise NotImplementedError('FakeOsModule.open')

  def close(self, file_des):
    """Closes a file descriptor.

    Args:
      file_des: An integer file descriptor for the file object requested.

    Raises:
      OSError: bad file descriptor.
      TypeError: if file descriptor is not an integer.
    """
    fh = self.filesystem.GetOpenFile(file_des)
    fh.close()

  def read(self, file_des, num_bytes):
    """Reads number of bytes from a file descriptor, returns bytes read.

    Args:
      file_des: An integer file descriptor for the file object requested.
      num_bytes: Number of bytes to read from file.

    Returns:
      Bytes read from file.

    Raises:
      OSError: bad file descriptor.
      TypeError: if file descriptor is not an integer.
    """
    fh = self.filesystem.GetOpenFile(file_des)
    return fh.read(num_bytes)

  def write(self, file_des, contents):
    """Writes string to file descriptor, returns number of bytes written.

    Args:
      file_des: An integer file descriptor for the file object requested.
      contents: String of bytes to write to file.

    Returns:
      Number of bytes written.

    Raises:
      OSError: bad file descriptor.
      TypeError: if file descriptor is not an integer.
    """
    fh = self.filesystem.GetOpenFile(file_des)
    fh.write(contents)
    fh.flush()
    return len(contents)

  def fstat(self, file_des):
    """Returns the os.stat-like tuple for the FakeFile object of file_des.

    Args:
      file_des:  file descriptor of filesystem object to retrieve

    Returns:
      the os.stat_result object corresponding to entry_path

    Raises:
      OSError: if the filesystem object doesn't exist.
    """
    # stat should return the tuple representing return value of os.stat
    stats = self.filesystem.GetOpenFile(file_des).GetObject()
    st_obj = os.stat_result((stats.st_mode, stats.st_ino, stats.st_dev,
                             stats.st_nlink, stats.st_uid, stats.st_gid,
                             stats.st_size, stats.st_atime,
                             stats.st_mtime, stats.st_ctime))
    return st_obj

  def _ConfirmDir(self, target_directory):
    """Tests that the target is actually a directory, raising OSError if not.

    Args:
      target_directory:  path to the target directory within the fake
        filesystem

    Returns:
      the FakeFile object corresponding to target_directory

    Raises:
      OSError:  if the target is not a directory
    """
    try:
      directory = self.filesystem.GetObject(target_directory)
    except IOError as e:
      raise OSError(e.errno, e.strerror, target_directory)
    if not directory.st_mode & stat.S_IFDIR:
      raise OSError(errno.ENOTDIR,
                    'Fake os module: not a directory',
                    target_directory)
    return directory

  def umask(self, new_mask):
    """Change the current umask.

    Args:
      new_mask: An integer.

    Returns:
      The old mask.

    Raises:
      TypeError: new_mask is of an invalid type.
    """
    if not isinstance(new_mask, int):
      raise TypeError('an integer is required')
    old_umask = self.filesystem.umask
    self.filesystem.umask = new_mask
    return old_umask

  def chdir(self, target_directory):
    """Change current working directory to target directory.

    Args:
      target_directory:  path to new current working directory

    Raises:
      OSError: if user lacks permission to enter the argument directory or if
               the target is not a directory
    """
    target_directory = self.filesystem.ResolvePath(target_directory)
    self._ConfirmDir(target_directory)
    directory = self.filesystem.GetObject(target_directory)
    # A full implementation would check permissions all the way up the tree.
    if not directory.st_mode | PERM_EXE:
      raise OSError(errno.EACCES, 'Fake os module: permission denied',
                    directory)
    self.filesystem.cwd = target_directory

  def getcwd(self):
    """Return current working directory."""
    return self.filesystem.cwd

  def getcwdu(self):
    """Return current working directory. Deprecated in Python 3."""
    if sys.version_info >= (3, 0):
      raise AttributeError('no attribute getcwdu')
    return unicode(self.filesystem.cwd)

  def listdir(self, target_directory):
    """Returns a sorted list of filenames in target_directory.

    Args:
      target_directory:  path to the target directory within the fake
        filesystem

    Returns:
      a sorted list of file names within the target directory

    Raises:
      OSError:  if the target is not a directory
    """
    target_directory = self.filesystem.ResolvePath(target_directory)
    directory = self._ConfirmDir(target_directory)
    return sorted(directory.contents)

  def _ClassifyDirectoryContents(self, root):
    """Classify contents of a directory as files/directories.

    Args:
      root: (str) Directory to examine.

    Returns:
      (tuple) A tuple consisting of three values: the directory examined, a
      list containing all of the directory entries, and a list containing all
      of the non-directory entries.  (This is the same format as returned by
      the os.walk generator.)

    Raises:
      Nothing on its own, but be ready to catch exceptions generated by
      underlying mechanisms like os.listdir.
    """
    dirs = []
    files = []
    for entry in self.listdir(root):
      if self.path.isdir(self.path.join(root, entry)):
        dirs.append(entry)
      else:
        files.append(entry)
    return (root, dirs, files)

  def walk(self, top, topdown=True, onerror=None):
    """Performs an os.walk operation over the fake filesystem.

    Args:
      top:  root directory from which to begin walk
      topdown:  determines whether to return the tuples with the root as the
        first entry (True) or as the last, after all the child directory
        tuples (False)
      onerror:  if not None, function which will be called to handle the
        os.error instance provided when os.listdir() fails

    Yields:
      (path, directories, nondirectories) for top and each of its
      subdirectories.  See the documentation for the builtin os module for
      further details.
    """
    top = self.path.normpath(top)
    try:
      top_contents = self._ClassifyDirectoryContents(top)
    except OSError as e:
      top_contents = None
      if onerror is not None:
        onerror(e)

    if top_contents is not None:
      if topdown:
        yield top_contents

      for directory in top_contents[1]:
        for contents in self.walk(self.path.join(top, directory),
                                  topdown=topdown, onerror=onerror):
          yield contents

      if not topdown:
        yield top_contents

  def readlink(self, path):
    """Reads the target of a symlink.

    Args:
      path:  symlink to read the target of

    Returns:
      the string representing the path to which the symbolic link points.

    Raises:
      TypeError: if path is None
      OSError: (with errno=ENOENT) if path is not a valid path, or
               (with errno=EINVAL) if path is valid, but is not a symlink
    """
    if path is None:
      raise TypeError
    try:
      link_obj = self.filesystem.LResolveObject(path)
    except IOError:
      raise OSError(errno.ENOENT, 'Fake os module: path does not exist', path)
    if stat.S_IFMT(link_obj.st_mode) != stat.S_IFLNK:
      raise OSError(errno.EINVAL, 'Fake os module: not a symlink', path)
    return link_obj.contents

  def stat(self, entry_path):
    """Returns the os.stat-like tuple for the FakeFile object of entry_path.

    Args:
      entry_path:  path to filesystem object to retrieve

    Returns:
      the os.stat_result object corresponding to entry_path

    Raises:
      OSError: if the filesystem object doesn't exist.
    """
    # stat should return the tuple representing return value of os.stat
    try:
      stats = self.filesystem.ResolveObject(entry_path)
      st_obj = os.stat_result((stats.st_mode, stats.st_ino, stats.st_dev,
                               stats.st_nlink, stats.st_uid, stats.st_gid,
                               stats.st_size, stats.st_atime,
                               stats.st_mtime, stats.st_ctime))
      return st_obj
    except IOError as io_error:
      raise OSError(io_error.errno, io_error.strerror, entry_path)

  def lstat(self, entry_path):
    """Returns the os.stat-like tuple for entry_path, not following symlinks.

    Args:
      entry_path:  path to filesystem object to retrieve

    Returns:
      the os.stat_result object corresponding to entry_path

    Raises:
      OSError: if the filesystem object doesn't exist.
    """
    # stat should return the tuple representing return value of os.stat
    try:
      stats = self.filesystem.LResolveObject(entry_path)
      st_obj = os.stat_result((stats.st_mode, stats.st_ino, stats.st_dev,
                               stats.st_nlink, stats.st_uid, stats.st_gid,
                               stats.st_size, stats.st_atime,
                               stats.st_mtime, stats.st_ctime))
      return st_obj
    except IOError as io_error:
      raise OSError(io_error.errno, io_error.strerror, entry_path)

  def remove(self, path):
    """Removes the FakeFile object representing the specified file."""
    path = self.filesystem.NormalizePath(path)
    if self.path.isdir(path) and not self.path.islink(path):
      raise OSError(errno.EISDIR, "Is a directory: '%s'" % path)
    try:
      self.filesystem.RemoveObject(path)
    except IOError as e:
      raise OSError(e.errno, e.strerror, e.filename)

  # As per the documentation unlink = remove.
  unlink = remove

  def rename(self, old_file, new_file):
    """Adds a FakeFile object at new_file containing contents of old_file.

    Also removes the FakeFile object for old_file, and replaces existing
    new_file object, if one existed.

    Args:
      old_file:  path to filesystem object to rename
      new_file:  path to where the filesystem object will live after this call

    Raises:
      OSError:  if old_file does not exist.
      IOError:  if dirname(new_file) does not exist
    """
    old_file = self.filesystem.NormalizePath(old_file)
    new_file = self.filesystem.NormalizePath(new_file)
    if not self.filesystem.Exists(old_file):
      raise OSError(errno.ENOENT,
                    'Fake os object: can not rename nonexistent file '
                    'with name',
                    old_file)
    if self.filesystem.Exists(new_file):
      if old_file == new_file:
        return None  # Nothing to do here.
      else:
        self.remove(new_file)
    old_dir, old_name = self.path.split(old_file)
    new_dir, new_name = self.path.split(new_file)
    if not self.filesystem.Exists(new_dir):
      raise IOError(errno.ENOENT, 'No such fake directory', new_dir)
    old_dir_object = self.filesystem.ResolveObject(old_dir)
    old_object = old_dir_object.GetEntry(old_name)
    old_object_mtime = old_object.st_mtime
    new_dir_object = self.filesystem.ResolveObject(new_dir)
    if old_object.st_mode & stat.S_IFDIR:
      old_object.name = new_name
      new_dir_object.AddEntry(old_object)
      old_dir_object.RemoveEntry(old_name)
    else:
      self.filesystem.CreateFile(new_file,
                                 st_mode=old_object.st_mode,
                                 contents=old_object.contents,
                                 create_missing_dirs=False)
      self.remove(old_file)
    new_object = self.filesystem.GetObject(new_file)
    new_object.SetMTime(old_object_mtime)
    self.chown(new_file, old_object.st_uid, old_object.st_gid)

  def rmdir(self, target_directory):
    """Remove a leaf Fake directory.

    Args:
      target_directory: (str) Name of directory to remove.

    Raises:
      OSError: if target_directory does not exist or is not a directory,
      or as per FakeFilesystem.RemoveObject. Cannot remove '.'.
    """
    if target_directory == '.':
      raise OSError(errno.EINVAL, 'Invalid argument: \'.\'')
    target_directory = self.filesystem.NormalizePath(target_directory)
    if self._ConfirmDir(target_directory):
      if self.listdir(target_directory):
        raise OSError(errno.ENOTEMPTY, 'Fake Directory not empty',
                      target_directory)
      try:
        self.filesystem.RemoveObject(target_directory)
      except IOError as e:
        raise OSError(e.errno, e.strerror, e.filename)

  def removedirs(self, target_directory):
    """Remove a leaf Fake directory and all empty intermediate ones."""
    target_directory = self.filesystem.NormalizePath(target_directory)
    directory = self._ConfirmDir(target_directory)
    if directory.contents:
      raise OSError(errno.ENOTEMPTY, 'Fake Directory not empty',
                    self.path.basename(target_directory))
    else:
      self.rmdir(target_directory)
    head, tail = self.path.split(target_directory)
    if not tail:
      head, tail = self.path.split(head)
    while head and tail:
      head_dir = self._ConfirmDir(head)
      if head_dir.contents:
        break
      self.rmdir(head)
      head, tail = self.path.split(head)

  def mkdir(self, dir_name, mode=PERM_DEF):
    """Create a leaf Fake directory.

    Args:
      dir_name: (str) Name of directory to create.  Relative paths are assumed
        to be relative to '/'.
      mode: (int) Mode to create directory with.  This argument defaults to
        0o777.  The umask is applied to this mode.

    Raises:
      OSError: if the directory name is invalid or parent directory is read only
      or as per FakeFilesystem.AddObject.
    """
    if dir_name.endswith(self.sep):
      dir_name = dir_name[:-1]

    parent_dir, _ = self.path.split(dir_name)
    if parent_dir:
      base_dir = self.path.normpath(parent_dir)
      if parent_dir.endswith(self.sep + '..'):
        base_dir, unused_dotdot, _ = parent_dir.partition(self.sep + '..')
      if not self.filesystem.Exists(base_dir):
        raise OSError(errno.ENOENT, 'No such fake directory', base_dir)

    dir_name = self.filesystem.NormalizePath(dir_name)
    if self.filesystem.Exists(dir_name):
      raise OSError(errno.EEXIST, 'Fake object already exists', dir_name)
    head, tail = self.path.split(dir_name)
    directory_object = self.filesystem.GetObject(head)
    if not directory_object.st_mode & PERM_WRITE:
      raise OSError(errno.EACCES, 'Permission Denied', dir_name)

    self.filesystem.AddObject(
        head, FakeDirectory(tail, mode & ~self.filesystem.umask))

  def makedirs(self, dir_name, mode=PERM_DEF):
    """Create a leaf Fake directory + create any non-existent parent dirs.

    Args:
      dir_name: (str) Name of directory to create.
      mode: (int) Mode to create directory (and any necessary parent
        directories) with. This argument defaults to 0o777.  The umask is
        applied to this mode.

    Raises:
      OSError: if the directory already exists or as per
      FakeFilesystem.CreateDirectory
    """
    dir_name = self.filesystem.NormalizePath(dir_name)
    path_components = self.filesystem.GetPathComponents(dir_name)

    # Raise a permission denied error if the first existing directory is not
    # writeable.
    current_dir = self.filesystem.root
    for component in path_components:
      if component not in current_dir.contents:
        if not current_dir.st_mode & PERM_WRITE:
          raise OSError(errno.EACCES, 'Permission Denied', dir_name)
        else:
          break
      else:
        current_dir = current_dir.contents[component]

    self.filesystem.CreateDirectory(dir_name, mode & ~self.filesystem.umask)

  def access(self, path, mode):
    """Check if a file exists and has the specified permissions.

    Args:
      path: (str) Path to the file.
      mode: (int) Permissions represented as a bitwise-OR combination of
          os.F_OK, os.R_OK, os.W_OK, and os.X_OK.
    Returns:
      boolean, True if file is accessible, False otherwise
    """
    try:
      st = self.stat(path)
    except OSError as os_error:
      if os_error.errno == errno.ENOENT:
        return False
      raise
    return (mode & ((st.st_mode >> 6) & 7)) == mode

  def chmod(self, path, mode):
    """Change the permissions of a file as encoded in integer mode.

    Args:
      path: (str) Path to the file.
      mode: (int) Permissions
    """
    try:
      file_object = self.filesystem.GetObject(path)
    except IOError as io_error:
      if io_error.errno == errno.ENOENT:
        raise OSError(errno.ENOENT,
                      'No such file or directory in fake filesystem',
                      path)
      raise
    file_object.st_mode = ((file_object.st_mode & ~PERM_ALL) |
                           (mode & PERM_ALL))
    file_object.st_ctime = int(time.time())

  def utime(self, path, times):
    """Change the access and modified times of a file.

    Args:
      path: (str) Path to the file.
      times: 2-tuple of numbers, of the form (atime, mtime) which is used to set
          the access and modified times, respectively. If None, file's access
          and modified times are set to the current time.

    Raises:
      TypeError: If anything other than integers is specified in passed tuple or
          number of elements in the tuple is not equal to 2.
    """
    try:
      file_object = self.filesystem.GetObject(path)
    except IOError as io_error:
      if io_error.errno == errno.ENOENT:
        raise OSError(errno.ENOENT,
                      'No such file or directory in fake filesystem',
                      path)
      raise
    if times is None:
      file_object.st_atime = int(time.time())
      file_object.st_mtime = int(time.time())
    else:
      if len(times) != 2:
        raise TypeError('utime() arg 2 must be a tuple (atime, mtime)')
      for t in times:
        if not isinstance(t, (int, float)):
          raise TypeError('an integer is required')

      file_object.st_atime = times[0]
      file_object.st_mtime = times[1]

  def chown(self, path, uid, gid):
    """Set ownership of a faked file.

    Args:
      path: (str) Path to the file or directory.
      uid: (int) Numeric uid to set the file or directory to.
      gid: (int) Numeric gid to set the file or directory to.
    """
    try:
      file_object = self.filesystem.GetObject(path)
    except IOError as io_error:
      if io_error.errno == errno.ENOENT:
        raise OSError(errno.ENOENT,
                      'No such file or directory in fake filesystem',
                      path)
      raise
    if uid != -1:
      file_object.st_uid = uid
    if gid != -1:
      file_object.st_gid = gid

  def mknod(self, filename, mode=None, device=None):
    """Create a filesystem node named 'filename'.

    Does not support device special files or named pipes as the real os
    module does.

    Args:
      filename: (str) Name of the file to create
      mode: (int) permissions to use and type of file to be created.
        Default permissions are 0o666.  Only the stat.S_IFREG file type
        is supported by the fake implementation.  The umask is applied
        to this mode.
      device: not supported in fake implementation

    Raises:
      OSError: if called with unsupported options or the file can not be
      created.
    """
    if mode is None:
      mode = stat.S_IFREG | PERM_DEF_FILE
    if device or not mode & stat.S_IFREG:
      raise OSError(errno.EINVAL,
                    'Fake os mknod implementation only supports '
                    'regular files.')

    head, tail = self.path.split(filename)
    if not tail:
      if self.filesystem.Exists(head):
        raise OSError(errno.EEXIST, 'Fake filesystem: %s: %s' % (
            os.strerror(errno.EEXIST), filename))
      raise OSError(errno.ENOENT, 'Fake filesystem: %s: %s' % (
          os.strerror(errno.ENOENT), filename))
    if tail == '.' or tail == '..' or self.filesystem.Exists(filename):
      raise OSError(errno.EEXIST, 'Fake fileystem: %s: %s' % (
          os.strerror(errno.EEXIST), filename))
    try:
      self.filesystem.AddObject(head, FakeFile(tail,
                                               mode & ~self.filesystem.umask))
    except IOError:
      raise OSError(errno.ENOTDIR, 'Fake filesystem: %s: %s' % (
          os.strerror(errno.ENOTDIR), filename))

  def symlink(self, link_target, path):
    """Creates the specified symlink, pointed at the specified link target.

    Args:
      link_target:  the target of the symlink
      path:  path to the symlink to create

    Returns:
      None

    Raises:
      IOError:  if the file already exists
    """
    self.filesystem.CreateLink(path, link_target)

  # pylint: disable-msg=C6002
  # TODO: Link doesn't behave like os.link, this needs to be fixed properly.
  link = symlink

  def __getattr__(self, name):
    """Forwards any unfaked calls to the standard os module."""
    return getattr(self._os_module, name)


class FakeFileOpen(object):
  """Faked file() and open() function replacements.

  Returns FakeFile objects in a FakeFilesystem in place of the file()
  or open() function.
  """

  def __init__(self, filesystem, delete_on_close=False):
    """init.

    Args:
      filesystem:  FakeFilesystem used to provide file system information
      delete_on_close:  optional boolean, deletes file on close()
    """
    self.filesystem = filesystem
    self._delete_on_close = delete_on_close

  def __call__(self, *args, **kwargs):
    """Redirects calls to file() or open() to appropriate method."""
    if sys.version_info < (3, 0):
      return self._call_ver2(*args, **kwargs)
    else:
      return self.Call(*args, **kwargs)

  def _call_ver2(self, file_path, mode='r', buffering=-1, flags=None):
    """Limits args of open() or file() for Python 2.x versions."""
    # Backwards compatibility, mode arg used to be named flags
    mode = flags or mode
    return self.Call(file_path, mode, buffering)

  def Call(self, file_, mode='r', buffering=-1, encoding=None,
           errors=None, newline=None, closefd=True, opener=None):
    """Returns a StringIO object with the contents of the target file object.

    Args:
      file_: path to target file or a file descriptor
      mode: additional file modes. All r/w/a r+/w+/a+ modes are supported.
        't', and 'U' are ignored, e.g., 'wU' is treated as 'w'. 'b' sets
        binary mode, no end of line translations in StringIO.
      buffering: ignored. (Used for signature compliance with __builtin__.open)
      encoding: ignored, strings have no encoding
      errors: ignored, this relates to encoding
      newline: controls universal newlines, passed to StringIO object
      closefd: if a file descriptor rather than file name is passed, and set
        to false, then the file descriptor is kept open when file is closed
      opener: not supported

    Returns:
      a StringIO object containing the contents of the target file

    Raises:
      IOError: if the target object is a directory, the path is invalid or
        permission is denied.
    """
    orig_modes = mode  # Save original mdoes for error messages.
    # Binary mode for non 3.x or set by mode
    binary = sys.version_info < (3, 0) or 'b' in mode
    # Normalize modes. Ignore 't' and 'U'.
    mode = mode.replace('t', '').replace('b', '')
    mode = mode.replace('rU', 'r').replace('U', 'r')

    if mode not in _OPEN_MODE_MAP:
      raise IOError('Invalid mode: %r' % orig_modes)

    must_exist, need_read, need_write, truncate, append = _OPEN_MODE_MAP[mode]

    file_object = None
    filedes = None
    # opening a file descriptor
    if isinstance(file_, int):
      filedes = file_
      file_object = self.filesystem.GetOpenFile(filedes).GetObject()
      file_path = file_object.name
    else:
      file_path = file_
      real_path = self.filesystem.ResolvePath(file_path)
      if self.filesystem.Exists(file_path):
        file_object = self.filesystem.GetObjectFromNormalizedPath(real_path)
      closefd = True

    if file_object:
      if ((need_read and not file_object.st_mode & PERM_READ) or
          (need_write and not file_object.st_mode & PERM_WRITE)):
        raise IOError(errno.EACCES, 'Permission denied', file_path)
      if need_write:
        file_object.st_ctime = int(time.time())
        if truncate:
          file_object.SetContents('')
    else:
      if must_exist:
        raise IOError(errno.ENOENT, 'No such file or directory', file_path)
      file_object = self.filesystem.CreateFile(
          real_path, create_missing_dirs=False, apply_umask=True)

    if file_object.st_mode & stat.S_IFDIR:
      raise IOError(errno.EISDIR, 'Fake file object: is a directory', file_path)

    class FakeFileWrapper(object):
      """Wrapper for a StringIO object for use by a FakeFile object.

      If the wrapper has any data written to it, it will propagate to
      the FakeFile object on close() or flush().
      """
      if sys.version_info < (3, 0):
        _OPERATION_ERROR = IOError
      else:
        _OPERATION_ERROR = io.UnsupportedOperation

      def __init__(self, file_object, update=False, read=False, append=False,
                   delete_on_close=False, filesystem=None, newline=None,
                   binary=True, closefd=True):
        self._file_object = file_object
        self._append = append
        self._read = read
        self._update = update
        self._closefd = closefd
        self._file_epoch = file_object.epoch
        contents = file_object.contents
        newline_arg = {} if binary else {'newline': newline}
        io_class = io.StringIO
        # For Python 3, files opened as binary only read/write byte contents.
        if sys.version_info >= (3, 0) and binary:
          io_class = io.BytesIO
          if contents and isinstance(contents, str):
            contents = bytes(contents, 'ascii')
        if contents:
          if update:
            self._io = io_class(**newline_arg)
            self._io.write(contents)
            if not append:
              self._io.seek(0)
            else:
              self._read_whence = 0
              if read:
                self._read_seek = 0
              else:
                self._read_seek = self._io.tell()
          else:
            self._io = io_class(contents, **newline_arg)
        else:
          self._io = io_class(**newline_arg)
          self._read_whence = 0
          self._read_seek = 0
        if delete_on_close:
          assert filesystem, 'delete_on_close=True requires filesystem='
        self._filesystem = filesystem
        self._delete_on_close = delete_on_close
        # override, don't modify FakeFile.name, as FakeFilesystem expects
        # it to be the file name only, no directories.
        self.name = file_object.opened_as

      def __enter__(self):
        """To support usage of this fake file with the 'with' statement."""
        return self

      def __exit__(self, type, value, traceback):  # pylint: disable-msg=W0622
        """To support usage of this fake file with the 'with' statement."""
        self.close()

      def GetObject(self):
        """Returns FakeFile object that is wrapped by current class."""
        return self._file_object

      def fileno(self):
        """Returns file descriptor of file object."""
        return self.filedes

      def close(self):
        """File close."""
        if self._update:
          self._file_object.SetContents(self._io.getvalue())
        if self._closefd:
          self._filesystem.CloseOpenFile(self)
        if self._delete_on_close:
          self._filesystem.RemoveObject(self.name)

      def flush(self):
        """Flush file contents to 'disk'."""
        if self._update:
          self._file_object.SetContents(self._io.getvalue())
          self._file_epoch = self._file_object.epoch

      def seek(self, offset, whence=0):
        """Move read/write pointer in 'file'."""
        if not self._append:
          self._io.seek(offset, whence)
        else:
          self._read_seek = offset
          self._read_whence = whence

      def tell(self):
        """Return the file's current position.

        Returns:
          int, file's current position in bytes.
        """
        if not self._append:
          return self._io.tell()
        if self._read_whence:
          write_seek = self._io.tell()
          self._io.seek(self._read_seek, self._read_whence)
          self._read_seek = self._io.tell()
          self._read_whence = 0
          self._io.seek(write_seek)
        return self._read_seek

      def _UpdateStringIO(self):
        """Updates the StringIO with changes to the file object contents."""
        if self._file_epoch == self._file_object.epoch:
          return
        whence = self._io.tell()
        self._io.seek(0)
        self._io.truncate()
        self._io.write(self._file_object.contents)
        self._io.seek(whence)
        self._file_epoch = self._file_object.epoch

      def _ReadWrappers(self, name):
        """Wrap a StringIO attribute in a read wrapper.

        Returns a read_wrapper which tracks our own read pointer since the
        StringIO object has no concept of a different read and write pointer.

        Args:
          name: the name StringIO attribute to wrap.  Should be a read call.

        Returns:
          either a read_error or read_wrapper function.
        """
        io_attr = getattr(self._io, name)

        def read_wrapper(*args, **kwargs):
          """Wrap all read calls to the StringIO Object.

          We do this to track the read pointer separate from the write
          pointer.  Anything that wants to read from the StringIO object
          while we're in append mode goes through this.

          Args:
            *args: pass through args
            **kwargs: pass through kwargs
          Returns:
            Wrapped StringIO object method
          """
          self._io.seek(self._read_seek, self._read_whence)
          ret_value = io_attr(*args, **kwargs)
          self._read_seek = self._io.tell()
          self._read_whence = 0
          self._io.seek(0, 2)
          return ret_value
        return read_wrapper

      def _OtherWrapper(self, name):
        """Wrap a StringIO attribute in an other_wrapper.

        Args:
          name: the name of the StringIO attribute to wrap.

        Returns:
          other_wrapper which is described below.
        """
        io_attr = getattr(self._io, name)

        def other_wrapper(*args, **kwargs):
          """Wrap all other calls to the StringIO Object.

          We do this to track changes to the write pointer.  Anything that
          moves the write pointer in a file open for appending should move
          the read pointer as well.

          Args:
            *args: pass through args
            **kwargs: pass through kwargs
          Returns:
            Wrapped StringIO object method
          """
          write_seek = self._io.tell()
          ret_value = io_attr(*args, **kwargs)
          if write_seek != self._io.tell():
            self._read_seek = self._io.tell()
            self._read_whence = 0
            self._file_object.st_size += (self._read_seek - write_seek)
          return ret_value
        return other_wrapper

      def Size(self):
        return self._file_object.st_size

      def __getattr__(self, name):
        if self._file_object.IsLargeFile():
          raise FakeLargeFileIoException(file_path)

        # errors on called method vs. open mode
        if not self._read and name.startswith('read'):
          def read_error(*args, **kwargs):
            """Throw an error unless the argument is zero."""
            if args and args[0] == 0:
              return ''
            raise self._OPERATION_ERROR('File is not open for reading.')
          return read_error
        if not self._update and (name.startswith('write')
                                 or name == 'truncate'):
          def write_error(*args, **kwargs):
            """Throw an error."""
            raise self._OPERATION_ERROR('File is not open for writing.')
          return write_error

        if name.startswith('read'):
          self._UpdateStringIO()
        if self._append:
          if name.startswith('read'):
            return self._ReadWrappers(name)
          else:
            return self._OtherWrapper(name)
        return getattr(self._io, name)

      def __iter__(self):
        if not self._read:
          raise self._OPERATION_ERROR('File is not open for reading')
        return self._io.__iter__()

    # if you print obj.name, the argument to open() must be printed. Not the
    # abspath, not the filename, but the actual argument.
    file_object.opened_as = file_path

    fakefile = FakeFileWrapper(file_object,
                               update=need_write,
                               read=need_read,
                               append=append,
                               delete_on_close=self._delete_on_close,
                               filesystem=self.filesystem,
                               newline=newline,
                               binary=binary,
                               closefd=closefd)
    if filedes is not None:
      fakefile.filedes = filedes
    else:
      fakefile.filedes = self.filesystem.AddOpenFile(fakefile)
    return fakefile
 

def _RunDoctest():
  # pylint: disable-msg=C6204
  import doctest
  import fake_filesystem  # pylint: disable-msg=W0406
  return doctest.testmod(fake_filesystem)


if __name__ == '__main__':
  _RunDoctest()
