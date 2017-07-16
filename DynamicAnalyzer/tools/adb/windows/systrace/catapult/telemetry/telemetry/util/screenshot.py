# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import logging
import os
import random
import tempfile

from py_utils import cloud_storage  # pylint: disable=import-error
from telemetry.util import image_util
from telemetry.internal.util import file_handle


def TryCaptureScreenShot(platform, tab=None):
  """ If the platform or tab supports screenshot, attempt to take a screenshot
  of the current browser.

  Args:
    platform: current platform
    tab: browser tab if available

  Returns:
    file handle of the tempoerary file path for the screenshot if
    present, None otherwise.
  """
  try:
    # TODO(nednguyen): once all platforms support taking screenshot,
    # remove the tab checking logic and consider moving this to story_runner.
    # (crbug.com/369490)
    if platform.CanTakeScreenshot():
      tf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
      tf.close()
      platform.TakeScreenshot(tf.name)
      return file_handle.FromTempFile(tf)
    elif tab and tab.IsAlive() and tab.screenshot_supported:
      tf = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
      tf.close()
      image = tab.Screenshot()
      image_util.WritePngFile(image, tf.name)
      return file_handle.FromTempFile(tf)
    else:
      logging.warning(
          'Either tab has crashed or browser does not support taking tab '
          'screenshot. Skip taking screenshot on failure.')
      return None
  except Exception as e:
    logging.warning('Exception when trying to capture screenshot: %s', repr(e))
    return None


def TryCaptureScreenShotAndUploadToCloudStorage(platform, tab=None):
  """ If the platform or tab supports screenshot, attempt to take a screenshot
  of the current browser.  If present it uploads this local path to cloud
  storage and returns the URL of the cloud storage path.

  Args:
    platform: current platform
    tab: browser tab if available

  Returns:
    url of the cloud storage path if screenshot is present, None otherwise
  """
  fh = TryCaptureScreenShot(platform, tab)
  if fh is not None:
    return _UploadScreenShotToCloudStorage(fh)

  return None

def _GenerateRemotePath(fh):
  return ('browser-screenshot_%s-%s%-d%s' % (
          fh.id,
          datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
          random.randint(1, 100000),
          fh.extension))

def _UploadScreenShotToCloudStorage(fh):
  """ Upload the given screenshot image to cloud storage and return the
    cloud storage url if successful.
  """
  try:
    return cloud_storage.Insert(cloud_storage.TELEMETRY_OUTPUT,
                                _GenerateRemotePath(fh), fh.GetAbsPath())
  except cloud_storage.CloudStorageError as err:
    logging.error('Cloud storage error while trying to upload screenshot: %s'
                  % repr(err))
    return '<Missing link>'
  finally:  # Must clean up screenshot file if exists.
    os.remove(fh.GetAbsPath())
