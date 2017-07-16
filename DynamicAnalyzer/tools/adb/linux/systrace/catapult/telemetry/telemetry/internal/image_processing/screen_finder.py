#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script attempts to detect the region of a camera's field of view that
# contains the screen of the device we are testing.
#
# Usage: ./screen_finder.py path_to_video 0 0 --verbose

from __future__ import division

import copy
import logging
import os
import sys

if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from telemetry.internal.image_processing import cv_util
from telemetry.internal.image_processing import frame_generator as \
    frame_generator_module
from telemetry.internal.image_processing import video_file_frame_generator
from telemetry.internal.util import external_modules

np = external_modules.ImportRequiredModule('numpy')
cv2 = external_modules.ImportRequiredModule('cv2')


class ScreenFinder(object):
  """Finds and extracts device screens from video.

  Sample Usage:
    sf = ScreenFinder(sys.argv[1])
    while sf.HasNext():
      ret, screen = sf.GetNext()

  Attributes:
    _lost_corners: Each index represents whether or not we lost track of that
        corner on the previous frame. Ordered by [top-right, top-left,
        bottom-left, bottom-right]
    _frame: An unmodified copy of the frame we're currently processing.
    _frame_debug: A copy of the frame we're currently processing, may be
        modified at any time, used for debugging.
    _frame_grey: A greyscale copy of the frame we're currently processing.
    _frame_edges: A Canny Edge detected copy of the frame we're currently
        processing.
    _screen_size: The size of device screen in the video when first detected.
    _avg_corners: Exponentially weighted average of the previous corner
        locations.
    _prev_corners: The location of the corners in the previous frame.
    _lost_corner_frames: A counter of the number of successive frames in which
        we've lost a corner location.
    _border: See |border| above.
    _min_line_length: The minimum length a line must be before we consider it
        a possible screen edge.
    _frame_generator: See |frame_generator| above.
    _width, _height: The width and height of the frame.
    _anglesp5, _anglesm5: The angles for each point we look at in the grid
        when computing brightness, constant across frames."""

  class ScreenNotFoundError(Exception):
    pass

  # Square of the distance a corner can travel in pixels between frames
  MAX_INTERFRAME_MOTION = 25
  # The minimum width line that may be considered a screen edge.
  MIN_SCREEN_WIDTH = 40
  # Number of frames with lost corners before we ignore MAX_INTERFRAME_MOTION
  RESET_AFTER_N_BAD_FRAMES = 2
  # The weight applied to the new screen location when exponentially averaging
  # screen location.
  # TODO(mthiesse): This should be framerate dependent, for lower framerates
  # this value should approach 1. For higher framerates, this value should
  # approach 0. The current 0.5 value works well in testing with 240 FPS.
  CORNER_AVERAGE_WEIGHT = 0.5

  # TODO(mthiesse): Investigate how to select the constants used here. In very
  # bright videos, twice as bright may be too high, and the minimum of 60 may
  # be too low.
  # The factor by which a quadrant at an intersection must be brighter than
  # the other quadrants to be considered a screen corner.
  MIN_RELATIVE_BRIGHTNESS_FACTOR = 1.5
  # The minimum average brightness required of an intersection quadrant to
  # be considered a screen corner (on a scale of 0-255).
  MIN_CORNER_ABSOLUTE_BRIGHTNESS = 60

  # Low and high hysteresis parameters to be passed to the Canny edge
  # detection algorithm.
  CANNY_HYSTERESIS_THRESH_LOW = 300
  CANNY_HYSTERESIS_THRESH_HIGH = 500

  SMALL_ANGLE = 5 / 180 * np.pi  # 5 degrees in radians

  DEBUG = False

  def __init__(self, frame_generator, border=5):
    """Initializes the ScreenFinder object.

    Args:
      frame_generator: FrameGenerator, An initialized Video Frame Generator.
      border: int, number of pixels of border to be kept when cropping the
          detected screen.

    Raises:
      FrameReadError: The frame generator may output a read error during
          initialization."""
    assert isinstance(frame_generator, frame_generator_module.FrameGenerator)
    self._lost_corners = [False, False, False, False]
    self._frame_debug = None
    self._frame = None
    self._frame_grey = None
    self._frame_edges = None
    self._screen_size = None
    self._avg_corners = None
    self._prev_corners = None
    self._lost_corner_frames = 0
    self._border = border
    self._min_line_length = self.MIN_SCREEN_WIDTH
    self._frame_generator = frame_generator
    self._anglesp5 = None
    self._anglesm5 = None

    if not self._InitNextFrame():
      logging.warn('Not enough frames in video feed!')
      return

    self._height, self._width = self._frame.shape[:2]

  def _InitNextFrame(self):
    """Called after processing each frame, reads in the next frame to ensure
    HasNext() is accurate."""
    self._frame_debug = None
    self._frame = None
    self._frame_grey = None
    self._frame_edges = None
    try:
      frame = next(self._frame_generator.Generator)
    except StopIteration:
      return False
    self._frame = frame
    self._frame_debug = copy.copy(frame)
    self._frame_grey = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    self._frame_edges = cv2.Canny(self._frame_grey,
                                  self.CANNY_HYSTERESIS_THRESH_LOW,
                                  self.CANNY_HYSTERESIS_THRESH_HIGH)
    return True

  def HasNext(self):
    """True if there are more frames available to process. """
    return self._frame is not None

  def GetNext(self):
    """Gets the next screen image.

    Returns:
      A numpy matrix containing the screen surrounded by the number of border
      pixels specified in initialization, and the location of the detected
      screen corners in the current frame, if a screen is found. The returned
      screen is guaranteed to be the same size at each frame.
      'None' and 'None' if no screen was found on the current frame.

    Raises:
      FrameReadError: An error occurred in the FrameGenerator.
      RuntimeError: This method was called when no frames were available."""
    if self._frame is None:
      raise RuntimeError('No more frames available.')

    logging.info('Processing frame: %d',
                 self._frame_generator.CurrentFrameNumber)

    # Finds straight lines in the image.
    hlines = cv2.HoughLinesP(self._frame_edges, 1, np.pi / 180, 60,
                             minLineLength=self._min_line_length,
                             maxLineGap=100)

    # Extends these straight lines to be long enough to ensure the screen edge
    # lines intersect.
    lines = cv_util.ExtendLines(np.float32(hlines[0]), 10000) \
        if hlines is not None else []

    # Find intersections in the lines; these are likely to be screen corners.
    intersections = self._FindIntersections(lines)
    if len(intersections[:, 0]) > 0:
      points = np.vstack(intersections[:, 0].flat)
      if (self._prev_corners is not None and len(points) >= 4 and
          not self._HasMovedFast(points, self._prev_corners)):
        corners = self._prev_corners
        missing_corners = 0
      else:
        # Extract the corners from all intersections.
        corners, missing_corners = self._FindCorners(
            intersections, self._frame_grey)
    else:
      corners = np.empty((4, 2), np.float32)
      corners[:] = np.nan
      missing_corners = 4

    screen = None
    found_screen = True
    final_corners = None
    try:
      # Handle the cases where we have missing corners.
      screen_corners = self._NewScreenLocation(
          corners, missing_corners, intersections)

      final_corners = self._SmoothCorners(screen_corners)

      # Create a perspective transform from our corners.
      transform, w, h = self._GetTransform(final_corners, self._border)

      # Apply the perspective transform to get our output.
      screen = cv2.warpPerspective(
          self._frame, transform, (int(w + 0.5), int(h + 0.5)))

      self._prev_corners = final_corners

    except self.ScreenNotFoundError as e:
      found_screen = False
      logging.info(e)

    if self.DEBUG:
      self._Debug(lines, corners, final_corners, screen)

    self._InitNextFrame()
    if found_screen:
      return screen, self._prev_corners
    return None, None

  def _FindIntersections(self, lines):
    """Finds intersections in a set of lines.

    Filters pairs of lines that are less than 45 degrees apart. Filtering
    these pairs helps dramatically reduce the number of points we have to
    process, as these points could not represent screen corners anyways.

    Returns:
      The intersections, represented as a tuple of (point, line, line) of the
      points and the lines that intersect there of all lines in the array that
      are more than 45 degrees apart."""
    intersections = np.empty((0, 3), np.float32)
    for i in xrange(0, len(lines)):
      for j in xrange(i + 1, len(lines)):
        # Filter lines that are less than 45 (or greater than 135) degrees
        # apart.
        if not cv_util.AreLinesOrthogonal(lines[i], lines[j], (np.pi / 4.0)):
          continue
        ret, point = cv_util.FindLineIntersection(lines[i], lines[j])
        point = np.float32(point)
        if not ret:
          continue
        # If we know where the previous corners are, we can also filter
        # intersections that are too far away from the previous corners to be
        # where the screen has moved.
        if self._prev_corners is not None and \
           self._lost_corner_frames <= self.RESET_AFTER_N_BAD_FRAMES and \
           not self._PointIsCloseToPreviousCorners(point):
          continue
        intersections = np.vstack((intersections,
                                   np.array((point, lines[i], lines[j]))))
    return intersections

  def _PointIsCloseToPreviousCorners(self, point):
    """True if the point is close to the previous corners."""
    max_dist = self.MAX_INTERFRAME_MOTION
    if cv_util.SqDistance(self._prev_corners[0], point) <= max_dist or \
       cv_util.SqDistance(self._prev_corners[1], point) <= max_dist or \
       cv_util.SqDistance(self._prev_corners[2], point) <= max_dist or \
       cv_util.SqDistance(self._prev_corners[3], point) <= max_dist:
      return True
    return False

  def _HasMovedFast(self, corners, prev_corners):
    min_dist = np.zeros(4, np.float32)
    for i in xrange(4):
      dist = np.min(cv_util.SqDistances(corners, prev_corners[i]))
      min_dist[i] = dist
    # 3 corners can move up to one pixel before we consider the screen to have
    # moved. TODO(mthiesse): Should this be relaxed? Resolution dependent?
    if np.sum(min_dist) < 3:
      return False
    return True

  class CornerData(object):

    def __init__(self, corner_index, corner_location, brightness_score, line1,
                 line2):
      self.corner_index = corner_index
      self.corner_location = corner_location
      self.brightness_score = brightness_score
      self.line1 = line1
      self.line2 = line2

    def __gt__(self, corner_data2):
      return self.corner_index > corner_data2.corner_index

    def __repr__(self):
      return ('\nCorner index: ' + str(self.corner_index) +
              ',\nCorner location: ' + str(self.corner_location) +
              ',\nBrightness score: ' + str(self.brightness_score) +
              ',\nline1: ' + str(self.line1) + ',\nline2: ' + str(self.line2))

  def _FindCorners(self, intersections, grey_frame):
    """Finds the screen corners in the image.

    Given the set of intersections in the image, finds the intersections most
    likely to be corners.

    Args:
      intersections: The array of intersections in the image.
      grey_frame: The greyscale frame we're processing.

    Returns:
      An array of length 4 containing the positions of the corners, or nan for
      each index where a corner could not be found, and a count of the number
      of missing corners.
      The corners are ordered as follows:
        1 | 0
        -----
        2 | 3
      Ex. 3 corners are found from a square of width 2 centered at the origin,
      the output would look like:
          '[[1, 1], [np.nan, np.nan], [-1, -1], [1, -1]], 1'"""
    filtered = []
    corners = np.empty((0, 2), np.float32)
    for corner_pos, score, point, line1, line2 in \
        self._LooksLikeCorner(intersections, grey_frame):
      if self.DEBUG:
        center = (int(point[0] + 0.5), int(point[1] + 0.5))
        cv2.circle(self._frame_debug, center, 5, (0, 255, 0), 1)
      point.resize(1, 2)
      corners = np.append(corners, point, axis=0)
      point.resize(2,)
      corner_data = self.CornerData(corner_pos, point, score, line1, line2)
      filtered.append(corner_data)

    # De-duplicate corners because we may have found many false positives, or
    # near-misses.
    self._DeDupCorners(filtered, corners)

    # Strip everything but the corner location.
    filtered_corners = np.array(
        [corner_data.corner_location for corner_data in filtered])
    corner_indices = [corner_data.corner_index for corner_data in filtered]

    # If we have found a corner to replace a lost corner, we want to check
    # that the corner is not erroneous by ensuring it makes a rectangle with
    # the 3 known good corners.
    if len(filtered) == 4:
      for i in xrange(4):
        point_info = (filtered[i].corner_location,
                      filtered[i].line1,
                      filtered[i].line2)
        if (self._lost_corners[i] and
            not self._PointConnectsToCorners(filtered_corners, point_info)):
          filtered_corners = np.delete(filtered_corners, i, 0)
          corner_indices = np.delete(corner_indices, i, 0)
          break

    # Ensure corners are sorted properly, inserting nans for missing corners.
    sorted_corners = np.empty((4, 2), np.float32)
    sorted_corners[:] = np.nan
    for i in xrange(len(filtered_corners)):
      sorted_corners[corner_indices[i]] = filtered_corners[i]

    # From this point on, our corners arrays are guaranteed to have 4
    # elements, though some may be nan.

    # Filter corners that have moved too far from the previous corner if we
    # are not resetting known corner information.
    reset_corners = (
        (self._lost_corner_frames > self.RESET_AFTER_N_BAD_FRAMES)
        and len(filtered_corners) == 4)
    if self._prev_corners is not None and not reset_corners:
      sqdists = cv_util.SqDistances(self._prev_corners, sorted_corners)
      for i in xrange(4):
        if np.isnan(sorted_corners[i][0]):
          continue
        if sqdists[i] > self.MAX_INTERFRAME_MOTION:
          sorted_corners[i] = np.nan

    real_corners = self._FindExactCorners(sorted_corners)
    missing_corners = np.count_nonzero(np.isnan(real_corners)) / 2
    return real_corners, missing_corners

  def _LooksLikeCorner(self, intersections, grey_frame):
    """Finds any intersections of lines that look like a screen corner.

    Args:
      intersections: The numpy array of points, and the lines that intersect
          at the given point.
      grey_frame: The greyscale frame we're processing.

    Returns:
      An array of: The corner location (0-3), the relative brightness score
      (to be used to de-duplicate corners later), the point, and the lines
      that make up the intersection, for all intersections that look like a
      corner."""
    points = np.vstack(intersections[:, 0].flat)
    lines1 = np.vstack(intersections[:, 1].flat)
    lines2 = np.vstack(intersections[:, 2].flat)
    # Map the image to four quadrants defined as the regions between each of
    # the lines that make up the intersection.
    line1a1 = np.pi - np.arctan2(lines1[:, 1] - points[:, 1],
                                 lines1[:, 0] - points[:, 0])
    line1a2 = np.pi - np.arctan2(lines1[:, 3] - points[:, 1],
                                 lines1[:, 2] - points[:, 0])
    line2a1 = np.pi - np.arctan2(lines2[:, 1] - points[:, 1],
                                 lines2[:, 0] - points[:, 0])
    line2a2 = np.pi - np.arctan2(lines2[:, 3] - points[:, 1],
                                 lines2[:, 2] - points[:, 0])
    line1a1 = line1a1.reshape(-1, 1)
    line1a2 = line1a2.reshape(-1, 1)
    line2a1 = line2a1.reshape(-1, 1)
    line2a2 = line2a2.reshape(-1, 1)

    line_angles = np.concatenate((line1a1, line1a2, line2a1, line2a2), axis=1)
    np.ndarray.sort(line_angles)

    # TODO(mthiesse): Investigate whether these should scale with image or
    # screen size. My intuition is that these don't scale with image size,
    # though they may be affected by image quality and how blurry the corners
    # are. See stackoverflow.com/q/7765810/ for inspiration.
    avg_range = 8.0
    num_points = 7

    points_m_avg = points - avg_range
    points_p_avg = points + avg_range
    # Exclude points near frame boundaries.
    include = np.where((points_m_avg[:, 0] > 0) & (points_m_avg[:, 1] > 0) &
                       (points_p_avg[:, 0] < self._width) &
                       (points_p_avg[:, 1] < self._height))
    line_angles = line_angles[include]
    points = points[include]
    lines1 = lines1[include]
    lines2 = lines2[include]
    points_m_avg = points_m_avg[include]
    points_p_avg = points_p_avg[include]
    # Perform a 2-d linspace to generate the x, y ranges for each
    # intersection.
    arr1 = points_m_avg[:, 0].reshape(-1, 1)
    arr2 = points_p_avg[:, 0].reshape(-1, 1)
    lin = np.linspace(0, 1, num_points)
    x_range = arr1 + (arr2 - arr1) * lin
    arr1 = points_m_avg[:, 1].reshape(-1, 1)
    arr2 = points_p_avg[:, 1].reshape(-1, 1)
    y_range = arr1 + (arr2 - arr1) * lin

    # The angles for each point we look at in the grid when computing
    # brightness are constant across frames, so we can generate them once.
    if self._anglesp5 is None:
      ind = np.transpose([np.tile(x_range[0], num_points),
                          np.repeat(y_range[0], num_points)])
      vectors = ind - points[0]
      angles = np.arctan2(vectors[:, 1], vectors[:, 0]) + np.pi
      self._anglesp5 = angles + self.SMALL_ANGLE
      self._anglesm5 = angles - self.SMALL_ANGLE
    results = []
    for i in xrange(len(y_range)):
      # Generate our filters for which points belong to which quadrant.
      one = np.where((self._anglesp5 <= line_angles[i, 1]) &
                     (self._anglesm5 >= line_angles[i, 0]))
      two = np.where((self._anglesp5 <= line_angles[i, 2]) &
                     (self._anglesm5 >= line_angles[i, 1]))
      thr = np.where((self._anglesp5 <= line_angles[i, 3]) &
                     (self._anglesm5 >= line_angles[i, 2]))
      fou = np.where((self._anglesp5 <= line_angles[i, 0]) |
                     (self._anglesm5 >= line_angles[i, 3]))
      # Take the cartesian product of our x and y ranges to get the full list
      # of pixels to look at.
      ind = np.transpose([np.tile(x_range[i], num_points),
                          np.repeat(y_range[i], num_points)])

      # Filter the full list by which indices belong to which quadrant, and
      # convert to integers so we can index with them.
      one_i = np.int32(np.rint(ind[one[0]]))
      two_i = np.int32(np.rint(ind[two[0]]))
      thr_i = np.int32(np.rint(ind[thr[0]]))
      fou_i = np.int32(np.rint(ind[fou[0]]))

      # Average the brightness of the pixels that belong to each quadrant.
      q_1 = np.average(grey_frame[one_i[:, 1], one_i[:, 0]])
      q_2 = np.average(grey_frame[two_i[:, 1], two_i[:, 0]])
      q_3 = np.average(grey_frame[thr_i[:, 1], thr_i[:, 0]])
      q_4 = np.average(grey_frame[fou_i[:, 1], fou_i[:, 0]])

      avg_intensity = [(q_4, 0), (q_1, 1), (q_2, 2), (q_3, 3)]
      # Sort by intensity.
      avg_intensity.sort(reverse=True)

      # Treat the point as a corner if one quadrant is at least twice as
      # bright as the next brightest quadrant, with a minimum brightness
      # requirement.
      tau = (2.0 * np.pi)
      min_factor = self.MIN_RELATIVE_BRIGHTNESS_FACTOR
      min_brightness = self.MIN_RELATIVE_BRIGHTNESS_FACTOR
      if avg_intensity[0][0] > avg_intensity[1][0] * min_factor and \
         avg_intensity[0][0] > min_brightness:
        bright_corner = avg_intensity[0][1]
        if bright_corner == 0:
          angle = np.pi - (line_angles[i, 0] + line_angles[i, 3]) / 2.0
          if angle < 0:
            angle = angle + tau
        else:
          angle = tau - (line_angles[i, bright_corner] +
                         line_angles[i, bright_corner - 1]) / 2.0
        score = avg_intensity[0][0] - avg_intensity[1][0]
        # TODO(mthiesse): int(angle / (pi / 2.0)) will break if the screen is
        # rotated through 45 degrees. Probably many other things will break as
        # well, movement of corners from one quadrant to another hasn't been
        # tested. We should support this eventually, but this is unlikely to
        # cause issues for any test setups.
        results.append((int(angle / (np.pi / 2.0)), score, points[i],
                        lines1[i], lines2[i]))
    return results

  def _DeDupCorners(self, corner_data, corners):
    """De-duplicate corners based on corner_index.

    For each set of points representing a corner: If one point is part of the
    rectangle and the other is not, filter the other one. If both or none are
    part of the rectangle, filter based on score (highest relative brightness
    of a quadrant). The reason we allow for neither to be part of the
    rectangle is because we may not have found all four corners of the
    rectangle, and in degenerate cases like this it's better to find 3 likely
    corners than none.

    Modifies corner_data directly.

    Args:
      corner_data: CornerData for each potential corner in the frame.
      corners: List of all potential corners in the frame."""
    # TODO(mthiesse): Ensure that the corners form a sensible rectangle. For
    # example, it is currently possible (but unlikely) to detect a 'screen'
    # where the bottom-left corner is above the top-left corner, while the
    # bottom-right corner is below the top-right corner.

    # Sort by corner_index to make de-duping easier.
    corner_data.sort()

    # De-dup corners.
    c_old = None
    for i in xrange(len(corner_data) - 1, 0, -1):
      if corner_data[i].corner_index != corner_data[i - 1].corner_index:
        c_old = None
        continue
      if c_old is None:
        point_info = (corner_data[i].corner_location,
                      corner_data[i].line1,
                      corner_data[i].line2)
        c_old = self._PointConnectsToCorners(corners, point_info, 2)
      point_info_new = (corner_data[i - 1].corner_location,
                        corner_data[i - 1].line1,
                        corner_data[i - 1].line2)
      c_new = self._PointConnectsToCorners(corners, point_info_new, 2)
      if (not (c_old or c_new)) or (c_old and c_new):
        if (corner_data[i].brightness_score <
            corner_data[i - 1].brightness_score):
          del corner_data[i]
          c_old = c_new
        else:
          del corner_data[i - 1]
      elif c_old:
        del corner_data[i - 1]
      else:
        del corner_data[i]
        c_old = c_new

  def _PointConnectsToCorners(self, corners, point_info, tolerance=1):
    """Checks if the lines of an intersection intersect with corners.

    This is useful to check if the point is part of a rectangle specified by
    |corners|.

    Args:
      point_info: A tuple of (point, line, line) representing an intersection
          of two lines.
      corners: corners that (hopefully) make up a rectangle.
      tolerance: The tolerance (approximately in pixels) of the distance
          between the corners and the lines for detecting if the point is on
          the line.

    Returns:
      True if each of the two lines that make up the intersection where the
      point is located connect the point to other corners."""
    line1_connected = False
    line2_connected = False
    point, line1, line2 = point_info
    for corner in corners:
      if corner is None:
        continue

      # Filter out points that are too close to one another to be different
      # corners.
      sqdist = cv_util.SqDistance(corner, point)
      if sqdist < self.MIN_SCREEN_WIDTH * self.MIN_SCREEN_WIDTH:
        continue

      line1_connected = line1_connected or \
          cv_util.IsPointApproxOnLine(corner, line1, tolerance)
      line2_connected = line2_connected or \
          cv_util.IsPointApproxOnLine(corner, line2, tolerance)
    if line1_connected and line2_connected:
      return True
    return False

  def _FindExactCorners(self, sorted_corners):
    """Attempts to find more accurate corner locations.

    Args:
      sorted_corners: The four screen corners, sorted by corner_index.

    Returns:
      A list of 4 probably more accurate corners, still sorted."""
    real_corners = np.empty((4, 2), np.float32)
    # Count missing corners, and search in a small area around our
    # intersections representing corners to see if we can find a more exact
    # corner, as the position of the intersections is noisy and not always
    # perfectly accurate.
    for i in xrange(4):
      corner = sorted_corners[i]
      if np.isnan(corner[0]):
        real_corners[i] = np.nan
        continue

      # Almost unbelievably, in edge cases with floating point error, the
      # width/height of the cropped corner image may be 2 or 4. This is fine
      # though, as long as the width and height of the cropped corner are not
      # hard-coded anywhere.
      corner_image = self._frame_edges[corner[1] - 1:corner[1] + 2,
                                       corner[0] - 1:corner[0] + 2]
      ret, p = self._FindExactCorner(i <= 1, i == 1 or i == 2, corner_image)
      if ret:
        if self.DEBUG:
          self._frame_edges[corner[1] - 1 + p[1]][corner[0] - 1 + p[0]] = 128
        real_corners[i] = corner - 1 + p
      else:
        real_corners[i] = corner
    return real_corners

  def _FindExactCorner(self, top, left, img):
    """Tries to finds the exact corner location for a given corner.

    Searches for the top or bottom, left or right most lit
    pixel in an edge-detected image, which should represent, with pixel
    precision, as accurate a corner location as possible. (Though perhaps
    up-sampling using cubic spline interpolation could get sub-pixel
    precision)

    TODO(mthiesse): This algorithm could be improved by including a larger
    region to search in, but would have to be made smarter about which lit
    pixels are on the detected screen edge and which are a not as it's
    currently extremely easy to fool by things like notification icons in
    screen corners.

    Args:
      top: boolean, whether or not we're looking for a top corner.
      left: boolean, whether or not we're looking for a left corner.
      img: A small cropping of the edge detected image in which to search.

    Returns:
      True and the location if a better corner location is found,
      False otherwise."""
    h, w = img.shape[:2]
    cy = 0
    starting_x = w - 1 if left else 0
    cx = starting_x
    if top:
      y_range = xrange(h - 1, -1, -1)
    else:
      y_range = xrange(0, h, 1)
    if left:
      x_range = xrange(w - 1, -1, -1)
    else:
      x_range = xrange(0, w, 1)
    for y in y_range:
      for x in x_range:
        if img[y][x] == 255:
          cy = y
          if (left and x <= cx) or (not left and x >= cx):
            cx = x
    if cx == starting_x and cy == 0 and img[0][starting_x] != 255:
      return False, (0, 0)
    return True, (cx, cy)

  def _NewScreenLocation(self, new_corners, missing_corners, intersections):
    """Computes the new screen location with best effort.

    Creates the final list of corners that represents the best effort attempt
    to find the new screen location. Handles degenerate cases where 3 or fewer
    new corners are present, using previous corner and intersection data.

    Args:
      new_corners: The corners found by our search for corners.
      missing_corners: The count of how many corners we're missing.
      intersections: The intersections of straight lines found in the current
          frame.

    Returns:
      An array of 4 new_corners hopefully representing the screen, or throws
      an error if this is not possible.

    Raises:
      ValueError: Finding the screen location was not possible."""
    screen_corners = copy.copy(new_corners)
    if missing_corners == 0:
      self._lost_corner_frames = 0
      self._lost_corners = [False, False, False, False]
      return screen_corners
    if self._prev_corners is None:
      raise self.ScreenNotFoundError(
          'Could not locate screen on frame %d' %
          self._frame_generator.CurrentFrameNumber)

    self._lost_corner_frames += 1
    if missing_corners > 1:
      logging.info('Unable to properly detect screen corners, making '
                   'potentially false assumptions on frame %d',
                   self._frame_generator.CurrentFrameNumber)
    # Replace missing new_corners with either nearest intersection to previous
    # corner, or previous corner if no intersections are found.
    for i in xrange(0, 4):
      if not np.isnan(new_corners[i][0]):
        self._lost_corners[i] = False
        continue
      self._lost_corners[i] = True
      min_dist = self.MAX_INTERFRAME_MOTION
      min_corner = None

      for isection in intersections:
        dist = cv_util.SqDistance(isection[0], self._prev_corners[i])
        if dist >= min_dist:
          continue
        if missing_corners == 1:
          # We know in this case that we have 3 corners present, meaning
          # all 4 screen lines, and therefore intersections near screen
          # corners present, so our new corner must connect to these
          # other corners.
          if not self._PointConnectsToCorners(new_corners, isection, 3):
            continue
        min_corner = isection[0]
        min_dist = dist
      screen_corners[i] = min_corner if min_corner is not None else \
          self._prev_corners[i]

    return screen_corners

  def _SmoothCorners(self, corners):
    """Smoothes the motion of corners, reduces noise.

    Smoothes the motion of corners by computing an exponentially weighted
    moving average of corner positions over time.

    Args:
      corners: The corners of the detected screen.

    Returns:
      The final corner positions."""
    if self._avg_corners is None:
      self._avg_corners = np.asfarray(corners, np.float32)
    for i in xrange(0, 4):
      # Keep an exponential moving average of the corner location to reduce
      # noise.
      new_contrib = np.multiply(self.CORNER_AVERAGE_WEIGHT, corners[i])
      old_contrib = np.multiply(1 - self.CORNER_AVERAGE_WEIGHT,
                                self._avg_corners[i])
      self._avg_corners[i] = np.add(new_contrib, old_contrib)

    return self._avg_corners

  def _GetTransform(self, corners, border):
    """Gets the perspective transform of the screen.

    Args:
      corners: The corners of the detected screen.
      border: The number of pixels of border to crop along with the screen.

    Returns:
      A perspective transform and the width and height of the target
      transform.

    Raises:
      ScreenNotFoundError: Something went wrong in detecting the screen."""
    if self._screen_size is None:
      w = np.sqrt(cv_util.SqDistance(corners[1], corners[0]))
      h = np.sqrt(cv_util.SqDistance(corners[1], corners[2]))
      if w < 1 or h < 1:
        raise self.ScreenNotFoundError(
            'Screen detected improperly (bad corners)')
      if min(w, h) < self.MIN_SCREEN_WIDTH:
        raise self.ScreenNotFoundError('Detected screen was too small.')

      self._screen_size = (w, h)
      # Extend min line length, if we can, to reduce the number of extraneous
      # lines the line finder finds.
      self._min_line_length = max(self._min_line_length, min(w, h) / 1.75)
    w = self._screen_size[0]
    h = self._screen_size[1]

    target = np.zeros((4, 2), np.float32)
    width = w + border
    height = h + border
    target[0] = np.asfarray((width, border))
    target[1] = np.asfarray((border, border))
    target[2] = np.asfarray((border, height))
    target[3] = np.asfarray((width, height))
    transform_w = width + border
    transform_h = height + border
    transform = cv2.getPerspectiveTransform(corners, target)
    return transform, transform_w, transform_h

  def _Debug(self, lines, corners, final_corners, screen):
    for line in lines:
      intline = ((int(line[0]), int(line[1])),
                 (int(line[2]), int(line[3])))
      cv2.line(self._frame_debug, intline[0], intline[1], (0, 0, 255), 1)
    i = 0
    for corner in corners:
      if not np.isnan(corner[0]):
        cv2.putText(
            self._frame_debug, str(i), (int(corner[0]), int(corner[1])),
            cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (255, 255, 0), 1, cv2.CV_AA)
        i += 1
    if final_corners is not None:
      for corner in final_corners:
        cv2.circle(self._frame_debug,
                   (int(corner[0]), int(corner[1])), 5, (255, 0, 255), 1)
    cv2.imshow('original', self._frame)
    cv2.imshow('debug', self._frame_debug)
    if screen is not None:
      cv2.imshow('screen', screen)
    cv2.waitKey()

# For being run as a script.
# TODO(mthiesse): To be replaced with a better standalone script.
# Ex: ./screen_finder.py path_to_video 0 5 --verbose


def main():
  start_frame = int(sys.argv[2]) if len(sys.argv) >= 3 else 0
  vf = video_file_frame_generator.VideoFileFrameGenerator(sys.argv[1],
                                                          start_frame)
  if len(sys.argv) >= 4:
    sf = ScreenFinder(vf, int(sys.argv[3]))
  else:
    sf = ScreenFinder(vf)
  # TODO(mthiesse): Use argument parser to improve command line parsing.
  if len(sys.argv) > 4 and sys.argv[4] == '--verbose':
    logging.basicConfig(format='%(message)s', level=logging.INFO)
  else:
    logging.basicConfig(format='%(message)s', level=logging.WARN)
  while sf.HasNext():
    sf.GetNext()

if __name__ == '__main__':
  main()
