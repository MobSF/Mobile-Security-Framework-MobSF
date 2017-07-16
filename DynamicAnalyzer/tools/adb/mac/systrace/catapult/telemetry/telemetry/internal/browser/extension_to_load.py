# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os

from telemetry.internal.backends.chrome import crx_id


class ExtensionPathNonExistentException(Exception):
  pass

class MissingPublicKeyException(Exception):
  pass

class ExtensionToLoad(object):
  def __init__(self, path, browser_type):
    if not os.path.isdir(path):
      raise ExtensionPathNonExistentException(
          'Extension path not a directory %s' % path)
    self._path = path
    self._local_path = path
    # It is possible that we are running telemetry on Windows targeting
    # a remote CrOS or Android device. In this case, we need the
    # browser_type argument to determine how we should encode
    # the extension path.
    self._is_win = (os.name == 'nt'
        and not (browser_type.startswith('android')
                 or browser_type.startswith('cros')))

  @property
  def extension_id(self):
    """Unique extension id of this extension."""
    if crx_id.HasPublicKey(self._path):
      # Calculate extension id from the public key.
      return crx_id.GetCRXAppID(os.path.realpath(self._path))
    else:
      # Calculate extension id based on the path on the device.
      return crx_id.GetCRXAppID(
          os.path.realpath(self._local_path),
          from_file_path=True,
          is_win_path=self._is_win)

  @property
  def path(self):
    """Path to extension source directory."""
    return self._path

  @property
  def local_path(self):
    """Path to extension destination directory, for remote instances of
    chrome"""
    return self._local_path

  @local_path.setter
  def local_path(self, local_path):
    self._local_path = local_path

