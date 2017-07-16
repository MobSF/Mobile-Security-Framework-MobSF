# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrappers for gsutil, for basic interaction with Google Cloud Storage."""

import collections
import contextlib
import hashlib
import logging
import os
import shutil
import stat
import subprocess
import re
import sys
import tempfile

import py_utils
from py_utils import lock

# Do a no-op import here so that cloud_storage_global_lock dep is picked up
# by https://cs.chromium.org/chromium/src/build/android/test_runner.pydeps.
# TODO(nedn, jbudorick): figure out a way to get rid of this ugly hack.
from py_utils import cloud_storage_global_lock  # pylint: disable=unused-import

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


PUBLIC_BUCKET = 'chromium-telemetry'
PARTNER_BUCKET = 'chrome-partner-telemetry'
INTERNAL_BUCKET = 'chrome-telemetry'
TELEMETRY_OUTPUT = 'chrome-telemetry-output'

# Uses ordered dict to make sure that bucket's key-value items are ordered from
# the most open to the most restrictive.
BUCKET_ALIASES = collections.OrderedDict((
    ('public', PUBLIC_BUCKET),
    ('partner', PARTNER_BUCKET),
    ('internal', INTERNAL_BUCKET),
    ('output', TELEMETRY_OUTPUT),
))

BUCKET_ALIAS_NAMES = BUCKET_ALIASES.keys()


_GSUTIL_PATH = os.path.join(py_utils.GetCatapultDir(), 'third_party', 'gsutil',
                            'gsutil')

# TODO(tbarzic): A workaround for http://crbug.com/386416 and
#     http://crbug.com/359293. See |_RunCommand|.
_CROS_GSUTIL_HOME_WAR = '/home/chromeos-test/'


# If Environment variables has DISABLE_CLOUD_STORAGE_IO set to '1', any method
# calls that invoke cloud storage network io will throw exceptions.
DISABLE_CLOUD_STORAGE_IO = 'DISABLE_CLOUD_STORAGE_IO'

# The maximum number of seconds to wait to acquire the pseudo lock for a cloud
# storage file before raising an exception.
LOCK_ACQUISITION_TIMEOUT = 10


class CloudStorageError(Exception):

  @staticmethod
  def _GetConfigInstructions():
    command = _GSUTIL_PATH
    if py_utils.IsRunningOnCrosDevice():
      command = 'HOME=%s %s' % (_CROS_GSUTIL_HOME_WAR, _GSUTIL_PATH)
    return ('To configure your credentials:\n'
            '  1. Run "%s config" and follow its instructions.\n'
            '  2. If you have a @google.com account, use that account.\n'
            '  3. For the project-id, just enter 0.' % command)


class PermissionError(CloudStorageError):

  def __init__(self):
    super(PermissionError, self).__init__(
        'Attempted to access a file from Cloud Storage but you don\'t '
        'have permission. ' + self._GetConfigInstructions())


class CredentialsError(CloudStorageError):

  def __init__(self):
    super(CredentialsError, self).__init__(
        'Attempted to access a file from Cloud Storage but you have no '
        'configured credentials. ' + self._GetConfigInstructions())


class CloudStorageIODisabled(CloudStorageError):
  pass


class NotFoundError(CloudStorageError):
  pass


class ServerError(CloudStorageError):
  pass


# TODO(tonyg/dtu): Can this be replaced with distutils.spawn.find_executable()?
def _FindExecutableInPath(relative_executable_path, *extra_search_paths):
  search_paths = list(extra_search_paths) + os.environ['PATH'].split(os.pathsep)
  for search_path in search_paths:
    executable_path = os.path.join(search_path, relative_executable_path)
    if py_utils.IsExecutable(executable_path):
      return executable_path
  return None


def _EnsureExecutable(gsutil):
  """chmod +x if gsutil is not executable."""
  st = os.stat(gsutil)
  if not st.st_mode & stat.S_IEXEC:
    os.chmod(gsutil, st.st_mode | stat.S_IEXEC)


def _RunCommand(args):
  # On cros device, as telemetry is running as root, home will be set to /root/,
  # which is not writable. gsutil will attempt to create a download tracker dir
  # in home dir and fail. To avoid this, override HOME dir to something writable
  # when running on cros device.
  #
  # TODO(tbarzic): Figure out a better way to handle gsutil on cros.
  #     http://crbug.com/386416, http://crbug.com/359293.
  gsutil_env = None
  if py_utils.IsRunningOnCrosDevice():
    gsutil_env = os.environ.copy()
    gsutil_env['HOME'] = _CROS_GSUTIL_HOME_WAR

  if os.name == 'nt':
    # If Windows, prepend python. Python scripts aren't directly executable.
    args = [sys.executable, _GSUTIL_PATH] + args
  else:
    # Don't do it on POSIX, in case someone is using a shell script to redirect.
    args = [_GSUTIL_PATH] + args
    _EnsureExecutable(_GSUTIL_PATH)

  if args[0] not in ('help', 'hash', 'version') and not IsNetworkIOEnabled():
    raise CloudStorageIODisabled(
        "Environment variable DISABLE_CLOUD_STORAGE_IO is set to 1. "
        'Command %s is not allowed to run' % args)

  gsutil = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=gsutil_env)
  stdout, stderr = gsutil.communicate()

  if gsutil.returncode:
    raise GetErrorObjectForCloudStorageStderr(stderr)

  return stdout


def GetErrorObjectForCloudStorageStderr(stderr):
  if (stderr.startswith((
      'You are attempting to access protected data with no configured',
      'Failure: No handler was ready to authenticate.')) or
      re.match('.*401.*does not have .* access to .*', stderr)):
    return CredentialsError()
  if ('status=403' in stderr or 'status 403' in stderr or
      '403 Forbidden' in stderr or
      re.match('.*403.*does not have .* access to .*', stderr)):
    return PermissionError()
  if (stderr.startswith('InvalidUriError') or 'No such object' in stderr or
      'No URLs matched' in stderr or 'One or more URLs matched no' in stderr):
    return NotFoundError(stderr)
  if '500 Internal Server Error' in stderr:
    return ServerError(stderr)
  return CloudStorageError(stderr)


def IsNetworkIOEnabled():
  """Returns true if cloud storage is enabled."""
  disable_cloud_storage_env_val = os.getenv(DISABLE_CLOUD_STORAGE_IO)

  if disable_cloud_storage_env_val and disable_cloud_storage_env_val != '1':
    logger.error(
        'Unsupported value of environment variable '
        'DISABLE_CLOUD_STORAGE_IO. Expected None or \'1\' but got %s.',
        disable_cloud_storage_env_val)

  return disable_cloud_storage_env_val != '1'


def List(bucket):
  query = 'gs://%s/' % bucket
  stdout = _RunCommand(['ls', query])
  return [url[len(query):] for url in stdout.splitlines()]


def Exists(bucket, remote_path):
  try:
    _RunCommand(['ls', 'gs://%s/%s' % (bucket, remote_path)])
    return True
  except NotFoundError:
    return False


def Move(bucket1, bucket2, remote_path):
  url1 = 'gs://%s/%s' % (bucket1, remote_path)
  url2 = 'gs://%s/%s' % (bucket2, remote_path)
  logger.info('Moving %s to %s', url1, url2)
  _RunCommand(['mv', url1, url2])


def Copy(bucket_from, bucket_to, remote_path_from, remote_path_to):
  """Copy a file from one location in CloudStorage to another.

  Args:
      bucket_from: The cloud storage bucket where the file is currently located.
      bucket_to: The cloud storage bucket it is being copied to.
      remote_path_from: The file path where the file is located in bucket_from.
      remote_path_to: The file path it is being copied to in bucket_to.

  It should: cause no changes locally or to the starting file, and will
  overwrite any existing files in the destination location.
  """
  url1 = 'gs://%s/%s' % (bucket_from, remote_path_from)
  url2 = 'gs://%s/%s' % (bucket_to, remote_path_to)
  logger.info('Copying %s to %s', url1, url2)
  _RunCommand(['cp', url1, url2])


def Delete(bucket, remote_path):
  url = 'gs://%s/%s' % (bucket, remote_path)
  logger.info('Deleting %s', url)
  _RunCommand(['rm', url])


def Get(bucket, remote_path, local_path):
  with _FileLock(local_path):
    _GetLocked(bucket, remote_path, local_path)


_CLOUD_STORAGE_GLOBAL_LOCK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'cloud_storage_global_lock.py')


@contextlib.contextmanager
def _FileLock(base_path):
  pseudo_lock_path = '%s.pseudo_lock' % base_path
  _CreateDirectoryIfNecessary(os.path.dirname(pseudo_lock_path))

  # Make sure that we guard the creation, acquisition, release, and removal of
  # the pseudo lock all with the same guard (_CLOUD_STORAGE_GLOBAL_LOCK).
  # Otherwise, we can get nasty interleavings that result in multiple processes
  # thinking they have an exclusive lock, like:
  #
  # (Process 1) Create and acquire the pseudo lock
  # (Process 1) Release the pseudo lock
  # (Process 1) Release the file lock
  # (Process 2) Open and acquire the existing pseudo lock
  # (Process 1) Delete the (existing) pseudo lock
  # (Process 3) Create and acquire a new pseudo lock
  #
  # Using the same guard for creation and removal of the pseudo lock guarantees
  # that all processes are referring to the same lock.
  pseudo_lock_fd = None
  pseudo_lock_fd_return = []
  py_utils.WaitFor(lambda: _AttemptPseudoLockAcquisition(pseudo_lock_path,
                                                         pseudo_lock_fd_return),
                   LOCK_ACQUISITION_TIMEOUT)
  pseudo_lock_fd = pseudo_lock_fd_return[0]

  try:
    yield
  finally:
    py_utils.WaitFor(lambda: _AttemptPseudoLockRelease(pseudo_lock_fd),
                     LOCK_ACQUISITION_TIMEOUT)

def _AttemptPseudoLockAcquisition(pseudo_lock_path, pseudo_lock_fd_return):
  """Try to acquire the lock and return a boolean indicating whether the attempt
  was successful. If the attempt was successful, pseudo_lock_fd_return, which
  should be an empty array, will be modified to contain a single entry: the file
  descriptor of the (now acquired) lock file.

  This whole operation is guarded with the global cloud storage lock, which
  prevents race conditions that might otherwise cause multiple processes to
  believe they hold the same pseudo lock (see _FileLock for more details).
  """
  pseudo_lock_fd = None
  try:
    with open(_CLOUD_STORAGE_GLOBAL_LOCK) as global_file:
      with lock.FileLock(global_file, lock.LOCK_EX | lock.LOCK_NB):
        # Attempt to acquire the lock in a non-blocking manner. If we block,
        # then we'll cause deadlock because another process will be unable to
        # acquire the cloud storage global lock in order to release the pseudo
        # lock.
        pseudo_lock_fd = open(pseudo_lock_path, 'w')
        lock.AcquireFileLock(pseudo_lock_fd, lock.LOCK_EX | lock.LOCK_NB)
        pseudo_lock_fd_return.append(pseudo_lock_fd)
        return True
  except (lock.LockException, IOError):
    # We failed to acquire either the global cloud storage lock or the pseudo
    # lock.
    if pseudo_lock_fd:
      pseudo_lock_fd.close()
    return False


def _AttemptPseudoLockRelease(pseudo_lock_fd):
  """Try to release the pseudo lock and return a boolean indicating whether
  the release was succesful.

  This whole operation is guarded with the global cloud storage lock, which
  prevents race conditions that might otherwise cause multiple processes to
  believe they hold the same pseudo lock (see _FileLock for more details).
  """
  pseudo_lock_path = pseudo_lock_fd.name
  try:
    with open(_CLOUD_STORAGE_GLOBAL_LOCK) as global_file:
      with lock.FileLock(global_file, lock.LOCK_EX | lock.LOCK_NB):
        lock.ReleaseFileLock(pseudo_lock_fd)
        pseudo_lock_fd.close()
        try:
          os.remove(pseudo_lock_path)
        except OSError:
          # We don't care if the pseudo lock gets removed elsewhere before
          # we have a chance to do so.
          pass
        return True
  except (lock.LockException, IOError):
    # We failed to acquire the global cloud storage lock and are thus unable to
    # release the pseudo lock.
    return False


def _CreateDirectoryIfNecessary(directory):
  if not os.path.exists(directory):
    os.makedirs(directory)


def _GetLocked(bucket, remote_path, local_path):
  url = 'gs://%s/%s' % (bucket, remote_path)
  logger.info('Downloading %s to %s', url, local_path)
  _CreateDirectoryIfNecessary(os.path.dirname(local_path))
  with tempfile.NamedTemporaryFile(
      dir=os.path.dirname(local_path),
      delete=False) as partial_download_path:
    try:
      # Windows won't download to an open file.
      partial_download_path.close()
      try:
        _RunCommand(['cp', url, partial_download_path.name])
      except ServerError:
        logger.info('Cloud Storage server error, retrying download')
        _RunCommand(['cp', url, partial_download_path.name])
      shutil.move(partial_download_path.name, local_path)
    finally:
      if os.path.exists(partial_download_path.name):
        os.remove(partial_download_path.name)


def Insert(bucket, remote_path, local_path, publicly_readable=False):
  """ Upload file in |local_path| to cloud storage.
  Args:
    bucket: the google cloud storage bucket name.
    remote_path: the remote file path in |bucket|.
    local_path: path of the local file to be uploaded.
    publicly_readable: whether the uploaded file has publicly readable
    permission.

  Returns:
    The url where the file is uploaded to.
  """
  url = 'gs://%s/%s' % (bucket, remote_path)
  command_and_args = ['cp']
  extra_info = ''
  if publicly_readable:
    command_and_args += ['-a', 'public-read']
    extra_info = ' (publicly readable)'
  command_and_args += [local_path, url]
  logger.info('Uploading %s to %s%s', local_path, url, extra_info)
  _RunCommand(command_and_args)
  return 'https://console.developers.google.com/m/cloudstorage/b/%s/o/%s' % (
      bucket, remote_path)


def GetIfHashChanged(cs_path, download_path, bucket, file_hash):
  """Downloads |download_path| to |file_path| if |file_path| doesn't exist or
     it's hash doesn't match |file_hash|.

  Returns:
    True if the binary was changed.
  Raises:
    CredentialsError if the user has no configured credentials.
    PermissionError if the user does not have permission to access the bucket.
    NotFoundError if the file is not in the given bucket in cloud_storage.
  """
  with _FileLock(download_path):
    if (os.path.exists(download_path) and
        CalculateHash(download_path) == file_hash):
      return False
    _GetLocked(bucket, cs_path, download_path)
    return True


def GetIfChanged(file_path, bucket):
  """Gets the file at file_path if it has a hash file that doesn't match or
  if there is no local copy of file_path, but there is a hash file for it.

  Returns:
    True if the binary was changed.
  Raises:
    CredentialsError if the user has no configured credentials.
    PermissionError if the user does not have permission to access the bucket.
    NotFoundError if the file is not in the given bucket in cloud_storage.
  """
  with _FileLock(file_path):
    hash_path = file_path + '.sha1'
    if not os.path.exists(hash_path):
      logger.warning('Hash file not found: %s', hash_path)
      return False

    expected_hash = ReadHash(hash_path)
    if os.path.exists(file_path) and CalculateHash(file_path) == expected_hash:
      return False
    _GetLocked(bucket, expected_hash, file_path)
    return True


def GetFilesInDirectoryIfChanged(directory, bucket):
  """ Scan the directory for .sha1 files, and download them from the given
  bucket in cloud storage if the local and remote hash don't match or
  there is no local copy.
  """
  if not os.path.isdir(directory):
    raise ValueError(
        '%s does not exist. Must provide a valid directory path.' % directory)
  # Don't allow the root directory to be a serving_dir.
  if directory == os.path.abspath(os.sep):
    raise ValueError('Trying to serve root directory from HTTP server.')
  for dirpath, _, filenames in os.walk(directory):
    for filename in filenames:
      path_name, extension = os.path.splitext(
          os.path.join(dirpath, filename))
      if extension != '.sha1':
        continue
      GetIfChanged(path_name, bucket)


def CalculateHash(file_path):
  """Calculates and returns the hash of the file at file_path."""
  sha1 = hashlib.sha1()
  with open(file_path, 'rb') as f:
    while True:
      # Read in 1mb chunks, so it doesn't all have to be loaded into memory.
      chunk = f.read(1024 * 1024)
      if not chunk:
        break
      sha1.update(chunk)
  return sha1.hexdigest()


def ReadHash(hash_path):
  with open(hash_path, 'rb') as f:
    return f.read(1024).rstrip()
