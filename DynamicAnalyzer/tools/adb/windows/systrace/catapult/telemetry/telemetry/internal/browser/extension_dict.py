# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.browser import extension_to_load


class ExtensionDict(object):
  """Dictionary of ExtensionPage instances, with extension_id as key."""

  def __init__(self, extension_backend):
    self._extension_backend = extension_backend

  def __getitem__(self, load_extension):
    """Given an ExtensionToLoad instance, returns the corresponding
    ExtensionPage instance."""
    if not isinstance(load_extension, extension_to_load.ExtensionToLoad):
      raise TypeError("Input param must be of type ExtensionToLoad")
    return self.GetByExtensionId(load_extension.extension_id)[0]

  def __contains__(self, load_extension):
    """Checks if this ExtensionToLoad instance has been loaded"""
    if not isinstance(load_extension, extension_to_load.ExtensionToLoad):
      raise TypeError("Input param must be of type ExtensionToLoad")
    return load_extension.extension_id in self._extension_backend

  def keys(self):
    return self._extension_backend.keys()

  def GetByExtensionId(self, extension_id):
    """Returns a list of extensions given an extension id. This is useful for
    connecting to built-in apps and component extensions."""
    return self._extension_backend[extension_id]
