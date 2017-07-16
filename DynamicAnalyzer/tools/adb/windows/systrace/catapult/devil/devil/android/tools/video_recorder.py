#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Captures a video from an Android device."""

import argparse
import logging
import os
import threading
import time
import sys

if __name__ == '__main__':
  sys.path.append(os.path.abspath(os.path.join(
      os.path.dirname(__file__), '..', '..', '..')))
from devil.android import device_signal
from devil.android import device_utils
from devil.android.tools import script_common
from devil.utils import cmd_helper
from devil.utils import reraiser_thread
from devil.utils import timeout_retry

logger = logging.getLogger(__name__)


class VideoRecorder(object):
  """Records a screen capture video from an Android Device (KitKat or newer)."""

  def __init__(self, device, megabits_per_second=4, size=None,
               rotate=False):
    """Creates a VideoRecorder instance.

    Args:
      device: DeviceUtils instance.
      host_file: Path to the video file to store on the host.
      megabits_per_second: Video bitrate in megabits per second. Allowed range
                           from 0.1 to 100 mbps.
      size: Video frame size tuple (width, height) or None to use the device
            default.
      rotate: If True, the video will be rotated 90 degrees.
    """
    self._bit_rate = megabits_per_second * 1000 * 1000
    self._device = device
    self._device_file = (
        '%s/screen-recording.mp4' % device.GetExternalStoragePath())
    self._recorder_thread = None
    self._rotate = rotate
    self._size = size
    self._started = threading.Event()

  def __enter__(self):
    self.Start()

  def Start(self, timeout=None):
    """Start recording video."""
    def screenrecord_started():
      return bool(self._device.GetPids('screenrecord'))

    if screenrecord_started():
      raise Exception("Can't run multiple concurrent video captures.")

    self._started.clear()
    self._recorder_thread = reraiser_thread.ReraiserThread(self._Record)
    self._recorder_thread.start()
    timeout_retry.WaitFor(
        screenrecord_started, wait_period=1, max_tries=timeout)
    self._started.wait(timeout)

  def _Record(self):
    cmd = ['screenrecord', '--verbose', '--bit-rate', str(self._bit_rate)]
    if self._rotate:
      cmd += ['--rotate']
    if self._size:
      cmd += ['--size', '%dx%d' % self._size]
    cmd += [self._device_file]
    for line in self._device.adb.IterShell(
        ' '.join(cmd_helper.SingleQuote(i) for i in cmd), None):
      if line.startswith('Content area is '):
        self._started.set()

  def __exit__(self, _exc_type, _exc_value, _traceback):
    self.Stop()

  def Stop(self):
    """Stop recording video."""
    if not self._device.KillAll('screenrecord', signum=device_signal.SIGINT,
                                quiet=True):
      logger.warning('Nothing to kill: screenrecord was not running')
    self._recorder_thread.join()

  def Pull(self, host_file=None):
    """Pull resulting video file from the device.

    Args:
      host_file: Path to the video file to store on the host.
    Returns:
      Output video file name on the host.
    """
    # TODO(jbudorick): Merge filename generation with the logic for doing so in
    # DeviceUtils.
    host_file_name = (
        host_file
        or 'screen-recording-%s-%s.mp4' % (
            str(self._device),
            time.strftime('%Y%m%dT%H%M%S', time.localtime())))
    host_file_name = os.path.abspath(host_file_name)
    self._device.PullFile(self._device_file, host_file_name)
    self._device.RemovePath(self._device_file, force=True)
    return host_file_name


def main():
  # Parse options.
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('-d', '--device', dest='devices', action='append',
                      help='Serial number of Android device to use.')
  parser.add_argument('--blacklist-file', help='Device blacklist JSON file.')
  parser.add_argument('-f', '--file', metavar='FILE',
                      help='Save result to file instead of generating a '
                           'timestamped file name.')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose logging.')
  parser.add_argument('-b', '--bitrate', default=4, type=float,
                      help='Bitrate in megabits/s, from 0.1 to 100 mbps, '
                           '%default mbps by default.')
  parser.add_argument('-r', '--rotate', action='store_true',
                      help='Rotate video by 90 degrees.')
  parser.add_argument('-s', '--size', metavar='WIDTHxHEIGHT',
                      help='Frame size to use instead of the device '
                           'screen size.')
  parser.add_argument('host_file', nargs='?',
                      help='File to which the video capture will be written.')

  args = parser.parse_args()

  host_file = args.host_file or args.file

  if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  size = (tuple(int(i) for i in args.size.split('x'))
          if args.size
          else None)

  def record_video(device, stop_recording):
    recorder = VideoRecorder(
        device, megabits_per_second=args.bitrate, size=size, rotate=args.rotate)
    with recorder:
      stop_recording.wait()

    f = None
    if host_file:
      root, ext = os.path.splitext(host_file)
      f = '%s_%s%s' % (root, str(device), ext)
    f = recorder.Pull(f)
    print 'Video written to %s' % os.path.abspath(f)

  parallel_devices = device_utils.DeviceUtils.parallel(
      script_common.GetDevices(args.devices, args.blacklist_file),
      async=True)
  stop_recording = threading.Event()
  running_recording = parallel_devices.pMap(record_video, stop_recording)
  print 'Recording. Press Enter to stop.',
  sys.stdout.flush()
  raw_input()
  stop_recording.set()

  running_recording.pGet(None)
  return 0


if __name__ == '__main__':
  sys.exit(main())
