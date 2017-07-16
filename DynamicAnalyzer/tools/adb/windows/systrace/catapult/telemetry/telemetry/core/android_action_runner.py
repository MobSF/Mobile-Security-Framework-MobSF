# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import time

from devil.android.sdk import keyevent

import py_utils


class ActionNotSupported(Exception):
  pass


class AndroidActionRunner(object):
  """Provides an API for interacting with an android device.

  This makes use of functionality provided by the android input command. None
  of the gestures here are guaranteed to be performant for telemetry tests and
  there is no official support for this API.

  TODO(ariblue): Replace this API with a better implementation for interacting
  with native components.
  """

  def __init__(self, platform_backend):
    self._platform_backend = platform_backend

  def SmoothScrollBy(self, left_start_coord, top_start_coord, direction,
                     scroll_distance):
    """Perform gesture to scroll down on the android device.
    """
    if direction not in ['down', 'up', 'left', 'right']:
      raise ActionNotSupported('Invalid scroll direction: %s' % direction)

    # This velocity is slower so that the exact distance we specify is the
    # distance the page travels.
    duration = scroll_distance

    # Note that the default behavior is swiping up for scrolling down.
    if direction == 'down':
      left_end_coord = left_start_coord
      top_end_coord = top_start_coord - scroll_distance
    elif direction == 'up':
      left_end_coord = left_start_coord
      top_end_coord = top_start_coord + scroll_distance
    elif direction == 'right':
      left_end_coord = left_start_coord - scroll_distance
      top_end_coord = top_start_coord
    elif direction == 'left':
      left_end_coord = left_start_coord + scroll_distance
      top_end_coord = top_start_coord

    self.InputSwipe(left_start_coord, top_start_coord, left_end_coord,
                    top_end_coord, duration)

  def Wait(self, seconds):
    """Wait for the number of seconds specified.

    Args:
      seconds: The number of seconds to wait.
    """
    time.sleep(seconds)

  def InputText(self, string):
    """Convert the characters of the string into key events and send to device.

    Args:
      string: The string to send to the device.
    """
    self._platform_backend.device.RunShellCommand(
        ['input', 'text', string], check_return=True)

  def InputKeyEvent(self, keycode):
    """Send a single key input to the device.

    See the devil.android.sdk.keyevent module for suitable keycode values.

    Args:
      keycode: A key code number that will be sent to the device.
    """
    self._platform_backend.device.SendKeyEvent(keycode)

  def InputTap(self, x_coord, y_coord):
    """Perform a tap input at the given coordinates.

    Args:
      x_coord: The x coordinate of the tap event.
      y_coord: The y coordinate of the tap event.
    """
    self._platform_backend.device.RunShellCommand(
        ['input', 'tap', str(x_coord), str(y_coord)], check_return=True)

  def InputSwipe(self, left_start_coord, top_start_coord, left_end_coord,
                 top_end_coord, duration):
    """Perform a swipe input.

    Args:
      left_start_coord: The horizontal starting coordinate of the gesture
      top_start_coord: The vertical starting coordinate of the gesture
      left_end_coord: The horizontal ending coordinate of the gesture
      top_end_coord: The vertical ending coordinate of the gesture
      duration: The length of time of the swipe in milliseconds
    """
    cmd = ['input', 'swipe']
    cmd.expand(str(x) for x in (left_start_coord, top_start_coord,
                                left_end_coord, top_end_coord, duration))
    self._platform_backend.device.RunShellCommand(cmd, check_return=True)

  def InputPress(self):
    """Perform a press input."""
    self._platform_backend.device.RunShellCommand(
        ['input', 'press'], check_return=True)

  def InputRoll(self, dx, dy):
    """Perform a roll input. This sends a simple zero-pressure move event.

    Args:
      dx: Change in the x coordinate due to move.
      dy: Change in the y coordinate due to move.
    """
    self._platform_backend.device.RunShellCommand(
        ['input', 'roll', str(dx), str(dy)], check_return=True)

  def TurnScreenOn(self):
    """If device screen is off, turn screen on.
    If the screen is already on, log a warning and return immediately.

    Raises:
      Timeout: If the screen is off and device fails to turn screen on.
    """
    self._platform_backend.device.SetScreen(True)
    py_utils.WaitFor(self._platform_backend.device.IsScreenOn, 5)

  def TurnScreenOff(self):
    """If device screen is on, turn screen off.
    If the screen is already off, log a warning and return immediately.

    Raises:
      Timeout: If the screen is on and device fails to turn screen off.
    """

    def is_screen_off():
      return not self._platform_backend.device.IsScreenOn()

    self._platform_backend.device.SetScreen(False)
    py_utils.WaitFor(is_screen_off, 5)

  def UnlockScreen(self):
    """If device screen is locked, unlocks it.
    If the device is not locked, log a warning and return immediately.

    Raises:
      Timeout: If device fails to unlock screen.
    """

    def is_screen_unlocked():
      return not self._platform_backend.IsScreenLocked()

    if self._platform_backend.IsScreenLocked():
      self.InputKeyEvent(keyevent.KEYCODE_MENU)
    else:
      logging.warning('Screen not locked when expected.')
      return

    py_utils.WaitFor(is_screen_unlocked, 5)
