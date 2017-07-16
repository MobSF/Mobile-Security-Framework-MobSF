# Copyright 2010 Google Inc. All Rights Reserved.
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

"""Fake tempfile module.

Fake implementation of the python2.4.1 tempfile built-in module that works with
a FakeFilesystem object.
"""
#pylint: disable-all

import errno
import logging
import os
import stat
import tempfile

import fake_filesystem

try:
  import StringIO as io  # pylint: disable-msg=C6204
except ImportError:
  import io  # pylint: disable-msg=C6204


class FakeTempfileModule(object):
  """Uses a FakeFilesystem to provide a mock for the tempfile 2.4.1 module.

  Common usage:
  filesystem = fake_filesystem.FakeFilesystem()
  my_tempfile_module = mock_tempfile.FakeTempfileModule(filesystem)

  See also: default keyword arguments for Dependency Injection on
  http://go/tott-episode-12
  """

  def __init__(self, filesystem):
    self._filesystem = filesystem
    self._tempfile = tempfile
    self.tempdir = None  # initialized by mktemp(), others
    self._temp_prefix = 'tmp'
    self._mktemp_retvals = []

  # pylint: disable-msg=W0622
  def _TempFilename(self, suffix='', prefix=None, dir=None):
    """Create a temporary filename that does not exist.

    This is a re-implementation of how tempfile creates random filenames,
    and is probably different.

    Does not modify self._filesystem, that's your job.

    Output: self.tempdir is initialized if unset
    Args:
      suffix: filename suffix
      prefix: filename prefix
      dir: dir to put filename in
    Returns:
      string, temp filename that does not exist
    """
    if dir is None:
      dir = self._filesystem.JoinPaths(self._filesystem.root.name, 'tmp')
    filename = None
    if prefix is None:
      prefix = self._temp_prefix
    while not filename or self._filesystem.Exists(filename):
      # pylint: disable-msg=W0212
      filename = self._filesystem.JoinPaths(dir, '%s%s%s' % (
          prefix,
          next(self._tempfile._RandomNameSequence()),
          suffix))
    return filename

  # pylint: disable-msg=W0622,W0613
  def TemporaryFile(self, mode='w+b', bufsize=-1,
                    suffix='', prefix=None, dir=None):
    """Return a file-like object deleted on close().

    Python 2.4.1 tempfile.TemporaryFile.__doc__ =
    >Return a file (or file-like) object that can be used as a temporary
    >storage area. The file is created using mkstemp. It will be destroyed as
    >soon as it is closed (including an implicit close when the object is
    >garbage collected). Under Unix, the directory entry for the file is
    >removed immediately after the file is created. Other platforms do not
    >support this; your code should not rely on a temporary file created using
    >this function having or not having a visible name in the file system.
    >
    >The mode parameter defaults to 'w+b' so that the file created can be read
    >and written without being closed. Binary mode is used so that it behaves
    >consistently on all platforms without regard for the data that is stored.
    >bufsize defaults to -1, meaning that the operating system default is used.
    >
    >The dir, prefix and suffix parameters are passed to mkstemp()

    Args:
      mode: optional string, see above
      bufsize: optional int, see above
      suffix: optional string, see above
      prefix: optional string, see above
      dir: optional string, see above
    Returns:
      a file-like object.
    """
    # pylint: disable-msg=C6002
    # TODO: prefix, suffix, bufsize, dir, mode unused?
    # cannot be cStringIO due to .name requirement below
    retval = io.StringIO()
    retval.name = '<fdopen>'  # as seen on 2.4.3
    return retval

  # pylint: disable-msg=W0622,W0613
  def NamedTemporaryFile(self, mode='w+b', bufsize=-1,
                         suffix='', prefix=None, dir=None, delete=True):
    """Return a file-like object with name that is deleted on close().

    Python 2.4.1 tempfile.NamedTemporaryFile.__doc__ =
    >This function operates exactly as TemporaryFile() does, except that
    >the file is guaranteed to have a visible name in the file system. That
    >name can be retrieved from the name member of the file object.

    Args:
      mode: optional string, see above
      bufsize: optional int, see above
      suffix: optional string, see above
      prefix: optional string, see above
      dir: optional string, see above
      delete: optional bool, see above
    Returns:
      a file-like object including obj.name
    """
    # pylint: disable-msg=C6002
    # TODO: bufsiz unused?
    temp = self.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    filename = temp[1]
    mock_open = fake_filesystem.FakeFileOpen(
        self._filesystem, delete_on_close=delete)
    obj = mock_open(filename, mode)
    obj.name = filename
    return obj

  # pylint: disable-msg=C6409
  def mkstemp(self, suffix='', prefix=None, dir=None, text=False):
    """Create temp file, returning a 2-tuple: (9999, filename).

    Important: Returns 9999 instead of a real file descriptor!

    Python 2.4.1 tempfile.mkstemp.__doc__ =
    >mkstemp([suffix, [prefix, [dir, [text]]]])
    >
    >User-callable function to create and return a unique temporary file.
    >The return value is a pair (fd, name) where fd is the file descriptor
    >returned by os.open, and name is the filename.
    >
    >...[snip args]...
    >
    >The file is readable and writable only by the creating user ID.
    >If the operating system uses permission bits to indicate whether
    >a file is executable, the file is executable by no one. The file
    >descriptor is not inherited by children of this process.
    >
    >Caller is responsible for deleting the file when done with it.

    NOTE: if dir is unspecified, this call creates a directory.

    Output: self.tempdir is initialized if unset
    Args:
      suffix: optional string, filename suffix
      prefix: optional string, filename prefix
      dir: optional string, directory for temp file; must exist before call
      text: optional boolean, True = open file in text mode.
          default False = open file in binary mode.
    Returns:
      2-tuple containing
      [0] = int, file descriptor number for the file object
      [1] = string, absolute pathname of a file
    Raises:
      OSError: when dir= is specified but does not exist
    """
    # pylint: disable-msg=C6002
    # TODO: optional boolean text is unused?
    # default dir affected by "global"
    filename = self._TempEntryname(suffix, prefix, dir)
    fh = self._filesystem.CreateFile(filename, st_mode=stat.S_IFREG|0o600)
    fd = self._filesystem.AddOpenFile(fh)

    self._mktemp_retvals.append(filename)
    return (fd, filename)

  # pylint: disable-msg=C6409
  def mkdtemp(self, suffix='', prefix=None, dir=None):
    """Create temp directory, returns string, absolute pathname.

    Python 2.4.1 tempfile.mkdtemp.__doc__ =
    >mkdtemp([suffix[, prefix[, dir]]])
    >Creates a temporary directory in the most secure manner
    >possible. [...]
    >
    >The user of mkdtemp() is responsible for deleting the temporary
    >directory and its contents when done with it.
    > [...]
    >mkdtemp() returns the absolute pathname of the new directory. [...]

    Args:
      suffix: optional string, filename suffix
      prefix: optional string, filename prefix
      dir: optional string, directory for temp dir. Must exist before call
    Returns:
      string, directory name
    """
    dirname = self._TempEntryname(suffix, prefix, dir)
    self._filesystem.CreateDirectory(dirname, perm_bits=0o700)

    self._mktemp_retvals.append(dirname)
    return dirname

  def _TempEntryname(self, suffix, prefix, dir):
    """Helper function for mk[ds]temp.

    Args:
      suffix: string, filename suffix
      prefix: string, filename prefix
      dir: string, directory for temp dir. Must exist before call
    Returns:
      string, entry name
    """
    # default dir affected by "global"
    if dir is None:
      call_mkdir = True
      dir = self.gettempdir()
    else:
      call_mkdir = False

    entryname = None
    while not entryname or self._filesystem.Exists(entryname):
      entryname = self._TempFilename(suffix=suffix, prefix=prefix, dir=dir)
    if not call_mkdir:
      # This is simplistic. A bad input of suffix=/f will cause tempfile
      # to blow up, but this mock won't.  But that's already a broken
      # corner case
      parent_dir = os.path.dirname(entryname)
      try:
        self._filesystem.GetObject(parent_dir)
      except IOError as err:
        assert 'No such file or directory' in str(err)
        # python -c 'import tempfile; tempfile.mkstemp(dir="/no/such/dr")'
        # OSError: [Errno 2] No such file or directory: '/no/such/dr/tmpFBuqjO'
        raise OSError(
            errno.ENOENT,
            'No such directory in mock filesystem',
            parent_dir)
    return entryname

  # pylint: disable-msg=C6409
  def gettempdir(self):
    """Get default temp dir.  Sets default if unset."""
    if self.tempdir:
      return self.tempdir
    # pylint: disable-msg=C6002
    # TODO: environment variables TMPDIR TEMP TMP, or other dirs?
    self.tempdir = '/tmp'
    return self.tempdir

  # pylint: disable-msg=C6409
  def gettempprefix(self):
    """Get temp filename prefix.

    NOTE: This has no effect on py2.4

    Returns:
      string, prefix to use in temporary filenames
    """
    return self._temp_prefix

  # pylint: disable-msg=C6409
  def mktemp(self, suffix=''):
    """mktemp is deprecated in 2.4.1, and is thus unimplemented."""
    raise NotImplementedError

  def _SetTemplate(self, template):
    """Setter for 'template' property."""
    self._temp_prefix = template
    logging.error('tempfile.template= is a NOP in python2.4')

  def __SetTemplate(self, template):
    """Indirect setter for 'template' property."""
    self._SetTemplate(template)

  def __DeprecatedTemplate(self):
    """template property implementation."""
    raise NotImplementedError

  # reading from template is deprecated, setting is ok.
  template = property(__DeprecatedTemplate, __SetTemplate,
                      doc="""Set the prefix for temp filenames""")

  def FakeReturnedMktempValues(self):
    """For validation purposes, mktemp()'s return values are stored."""
    return self._mktemp_retvals

  def FakeMktempReset(self):
    """Clear the stored mktemp() values."""
    self._mktemp_retvals = []
