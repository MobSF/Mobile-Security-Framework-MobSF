#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Use your keyboard as your phone's keyboard. Experimental."""

import argparse
import copy
import os
import sys
import termios
import tty

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   '..', '..', '..')))
from devil import base_error
from devil.android.sdk import keyevent
from devil.android.tools import script_common
from devil.utils import run_tests_helper


_KEY_MAPPING = {
  '\x08': keyevent.KEYCODE_DEL,
  '\x0a': keyevent.KEYCODE_ENTER,
  ' ': keyevent.KEYCODE_SPACE,
  '.': keyevent.KEYCODE_PERIOD,
  '0': keyevent.KEYCODE_0,
  '1': keyevent.KEYCODE_1,
  '2': keyevent.KEYCODE_2,
  '3': keyevent.KEYCODE_3,
  '4': keyevent.KEYCODE_4,
  '5': keyevent.KEYCODE_5,
  '6': keyevent.KEYCODE_6,
  '7': keyevent.KEYCODE_7,
  '8': keyevent.KEYCODE_8,
  '9': keyevent.KEYCODE_9,
  'a': keyevent.KEYCODE_A,
  'b': keyevent.KEYCODE_B,
  'c': keyevent.KEYCODE_C,
  'd': keyevent.KEYCODE_D,
  'e': keyevent.KEYCODE_E,
  'f': keyevent.KEYCODE_F,
  'g': keyevent.KEYCODE_G,
  'h': keyevent.KEYCODE_H,
  'i': keyevent.KEYCODE_I,
  'j': keyevent.KEYCODE_J,
  'k': keyevent.KEYCODE_K,
  'l': keyevent.KEYCODE_L,
  'm': keyevent.KEYCODE_M,
  'n': keyevent.KEYCODE_N,
  'o': keyevent.KEYCODE_O,
  'p': keyevent.KEYCODE_P,
  'q': keyevent.KEYCODE_Q,
  'r': keyevent.KEYCODE_R,
  's': keyevent.KEYCODE_S,
  't': keyevent.KEYCODE_T,
  'u': keyevent.KEYCODE_U,
  'v': keyevent.KEYCODE_V,
  'w': keyevent.KEYCODE_W,
  'x': keyevent.KEYCODE_X,
  'y': keyevent.KEYCODE_Y,
  'z': keyevent.KEYCODE_Z,
  '\x7f': keyevent.KEYCODE_DEL,
}


def Keyboard(device, stream_itr):
  try:
    for c in stream_itr:
      k = _KEY_MAPPING.get(c)
      if k:
        device.SendKeyEvent(k)
      else:
        print
        print '(No mapping for character 0x%x)' % ord(c)
  except KeyboardInterrupt:
    pass


def AddArguments(parser):
  parser.add_argument('-d', '--device', action='append', dest='devices',
                      metavar='DEVICE', help='device serial')
  parser.add_argument('-v', '--verbose', action='count', help='print more')


class MultipleDevicesError(base_error.BaseError):
  def __init__(self, devices):
    super(MultipleDevicesError, self).__init__(
        'More than one device found: %s' % ', '.join(str(d) for d in devices))


def main(raw_args):
  parser = argparse.ArgumentParser(
      description="Use your keyboard as your phone's keyboard.")
  AddArguments(parser)
  args = parser.parse_args(raw_args)

  run_tests_helper.SetLogLevel(args.verbose)

  devices = script_common.GetDevices(args.devices, None)
  if len(devices) > 1:
    raise MultipleDevicesError(devices)

  def next_char():
    while True:
      yield sys.stdin.read(1)

  try:
    fd = sys.stdin.fileno()

    # See man 3 termios for more info on what this is doing.
    old_attrs = termios.tcgetattr(fd)
    new_attrs = copy.deepcopy(old_attrs)
    new_attrs[tty.LFLAG] = new_attrs[tty.LFLAG] & ~(termios.ICANON)
    new_attrs[tty.CC][tty.VMIN] = 1
    new_attrs[tty.CC][tty.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSAFLUSH, new_attrs)

    Keyboard(devices[0], next_char())
  finally:
    termios.tcsetattr(fd, termios.TCSAFLUSH, old_attrs)
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
