# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class BaseTool(object):
  """A tool that does nothing."""
  # pylint: disable=R0201

  def __init__(self):
    """Does nothing."""
    pass

  def GetTestWrapper(self):
    """Returns a string that is to be prepended to the test command line."""
    return ''

  def GetUtilWrapper(self):
    """Returns the wrapper name for the utilities.

    Returns:
       A string that is to be prepended to the command line of utility
    processes (forwarder, etc.).
    """
    return ''

  @classmethod
  def CopyFiles(cls, device):
    """Copies tool-specific files to the device, create directories, etc."""
    pass

  def SetupEnvironment(self):
    """Sets up the system environment for a test.

    This is a good place to set system properties.
    """
    pass

  def CleanUpEnvironment(self):
    """Cleans up environment."""
    pass

  def GetTimeoutScale(self):
    """Returns a multiplier that should be applied to timeout values."""
    return 1.0

  def NeedsDebugInfo(self):
    """Whether this tool requires debug info.

    Returns:
      True if this tool can not work with stripped binaries.
    """
    return False
