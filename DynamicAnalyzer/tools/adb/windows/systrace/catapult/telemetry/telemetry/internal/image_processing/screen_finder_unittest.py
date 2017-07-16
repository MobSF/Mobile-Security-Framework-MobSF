# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import math
import os
import unittest

from telemetry.core import util
from telemetry.internal.util import external_modules

try:
  np = external_modules.ImportRequiredModule('numpy')
  cv2 = external_modules.ImportRequiredModule('cv2')
except (ImportError, NotImplementedError) as err:
  pass
else:
  # pylint: disable=protected-access
  class ScreenFinderTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
      super(ScreenFinderTest, self).__init__(*args, **kwargs)
      # Import modules with dependencies that may not be preset in test setup so
      # that importing this unit test doesn't cause the test runner to raise an
      # exception.
      from telemetry.internal.image_processing import fake_frame_generator
      from telemetry.internal.image_processing import screen_finder
      from telemetry.internal.image_processing import video_file_frame_generator
      self.FakeFrameGenerator = fake_frame_generator.FakeFrameGenerator
      self.VideoFileFrameGenerator = \
          video_file_frame_generator.VideoFileFrameGenerator
      self.ScreenFinder = screen_finder.ScreenFinder

    def _GetScreenFinder(self, video_filename):
      if not video_filename:
        fg = self.FakeFrameGenerator()
      else:
        vid = os.path.join(util.GetUnittestDataDir(), video_filename)
        fg = self.VideoFileFrameGenerator(vid)
      return self.ScreenFinder(fg)

    def testBasicFunctionality(self):
      def CheckCorners(corners, expected):
        for i in xrange(len(corners)):
          for j in xrange(len(corners[i])):
            self.assertAlmostEqual(corners[i][j], expected[i][j], delta=1.1)
      expected = [[314, 60], [168, 58], [162, 274], [311, 276]]
      sf = self._GetScreenFinder('screen_3_frames.mov')
      self.assertTrue(sf.HasNext())
      screen, corners = sf.GetNext()
      CheckCorners(corners, expected)
      self.assertIsNotNone(screen)
      height, width = screen.shape[:2]
      self.assertAlmostEqual(height, 226, delta=2)
      self.assertAlmostEqual(width, 156, delta=2)
      self.assertTrue(sf.HasNext())
      screen, corners = sf.GetNext()
      CheckCorners(corners, expected)
      self.assertIsNotNone(screen)
      height1, width1 = screen.shape[:2]
      self.assertEqual(width, width1)
      self.assertEqual(height, height1)
      self.assertTrue(sf.HasNext())
      screen, corners = sf.GetNext()
      CheckCorners(corners, expected)
      self.assertIsNotNone(screen)
      height2, width2 = screen.shape[:2]
      self.assertEqual(width, width2)
      self.assertEqual(height, height2)
      self.assertFalse(sf.HasNext())
      error = ''
      try:
        sf.GetNext()
      except RuntimeError as e:
        error = str(e)
      self.assertEqual(error, 'No more frames available.')

    def testHasMovedFast(self):
      sf = self._GetScreenFinder(None)
      prev_corners = np.asfarray(([1000, 1000], [0, 1000], [0, 0], [1000, 0]))
      self.assertFalse(sf._HasMovedFast(prev_corners, prev_corners))
      not_moved = copy.deepcopy(prev_corners)
      not_moved[0][1] += 1
      not_moved[1][1] += 1
      not_moved[3][0] += 0.9
      self.assertFalse(sf._HasMovedFast(not_moved, prev_corners))
      moved = copy.deepcopy(prev_corners)
      moved[0][1] += math.sqrt(0.5)
      moved[0][0] += math.sqrt(0.5)
      moved[1][1] += 2.1
      self.assertTrue(sf._HasMovedFast(moved, prev_corners))

    def testPointConnectsToCorners(self):
      sf = self._GetScreenFinder(None)
      line1 = np.asfarray(((0, 0, 1, 0)))
      line2 = np.asfarray(((0, 0, 0, 1)))
      point = np.asfarray((0, 0))
      point_info = (point, line1, line2)
      corners = np.asfarray(((1, 0), (0, 1)))
      self.assertFalse(sf._PointConnectsToCorners(corners, point_info, 1))
      corners = np.append(corners, (100, 1))
      corners = np.append(corners, (1, 100))
      corners = corners.reshape(-1, 2)
      self.assertTrue(sf._PointConnectsToCorners(corners, point_info, 2))
      self.assertFalse(sf._PointConnectsToCorners(corners, point_info, 0.5))
      corners = np.append(corners, (100, 0))
      corners = np.append(corners, (0, 100))
      corners = corners.reshape(-1, 2)
      self.assertTrue(sf._PointConnectsToCorners(corners, point_info, 0))

    def testFindIntersections(self):
      def _BuildResult(point, line1, line2):
        return [point, np.asfarray(line1).tolist(), np.asfarray(line2).tolist()]

      def _IntersectionResultsToList(results):
        result_list = []
        for result in results:
          point, line1, line2 = result
          p = np.round(point).tolist()
          l1 = np.round(line1).tolist()
          l2 = np.round(line2).tolist()
          result_list.append([p, l1, l2])
        return result_list

      sf = self._GetScreenFinder(None)
      expected = []
      lines = []
      # Box with corners at (0, 0), (1000, 0), (0, 1000), (1000, 1000)
      lines.append(np.asfarray(((0, 1001, 0, -1))))
      lines.append(np.asfarray(((-1, 0, 1001, 0))))
      lines.append(np.asfarray(((1000, 1001, 1000, -1))))
      lines.append(np.asfarray(((-1, 1000, 1001, 1000))))
      expected.append(_BuildResult([0, 0], lines[0], lines[1]))
      expected.append(_BuildResult([0, 1000], lines[0], lines[3]))
      expected.append(_BuildResult([1000, 0], lines[1], lines[2]))
      expected.append(_BuildResult([1000, 1000], lines[2], lines[3]))

      # crosses 2 lines at 45 degrees.
      lines.append(np.asfarray(((0, 500, 500, 0))))
      expected.append(_BuildResult([0, 500], lines[0], lines[4]))
      expected.append(_BuildResult([500, 0], lines[1], lines[4]))

      # crosses 1 line at > 45 degrees, 1 line at < 45 degrees.
      lines.append(np.asfarray(((0, 400, 600, 0))))
      expected.append(_BuildResult([0, 400], lines[0], lines[5]))

      # Test without previous corner data, all intersections should be found.
      results = sf._FindIntersections(lines)
      result_list = _IntersectionResultsToList(results)

      for e in expected:
        self.assertIn(e, result_list)
      self.assertEqual(len(expected), len(result_list))

      # Now introduce previous corners, but also reset conditions. No
      # intersections should be lost.
      corners = ((1000, 1000), (0, 1000), (0, 0), (1000, 0))
      sf._prev_corners = np.asfarray(corners, np.float32)
      sf._lost_corner_frames = sf.RESET_AFTER_N_BAD_FRAMES + 1
      results = sf._FindIntersections(lines)
      result_list = _IntersectionResultsToList(results)

      for e in expected:
        self.assertIn(e, result_list)
      self.assertEqual(len(expected), len(result_list))

      # Remove reset conditions, so intersections not near corners will be lost.
      sf._lost_corner_frames = sf.RESET_AFTER_N_BAD_FRAMES
      # First 4 intersections are the ones at the old corner locations.
      expected = expected[0:4]
      results = sf._FindIntersections(lines)
      result_list = _IntersectionResultsToList(results)

      for e in expected:
        self.assertIn(e, result_list)
      self.assertEqual(len(expected), len(result_list))

    def testPointIsCloseToPreviousCorners(self):
      sf = self._GetScreenFinder(None)
      corners = ((1000, 1000), (0, 1000), (0, 0), (1000, 0))
      sf._prev_corners = np.asfarray(corners, np.float32)
      dist = math.sqrt(sf.MAX_INTERFRAME_MOTION)
      sidedist1 = math.sqrt(sf.MAX_INTERFRAME_MOTION) / math.sqrt(2) - (1e-13)
      sidedist2 = math.sqrt(sf.MAX_INTERFRAME_MOTION) / math.sqrt(2) + (1e-13)
      point1 = (corners[3][0] + dist, corners[3][1])
      self.assertTrue(sf._PointIsCloseToPreviousCorners(point1))
      point2 = (corners[3][0] + sidedist1, corners[3][1] + sidedist1)
      self.assertTrue(sf._PointIsCloseToPreviousCorners(point2))
      point3 = (corners[1][0] + sidedist2, corners[1][1] + sidedist2)
      self.assertFalse(sf._PointIsCloseToPreviousCorners(point3))

    def testLooksLikeCorner(self):
      # TODO: Probably easier to just do end to end tests.
      pass

    def testCornerData(self):
      cd = self.ScreenFinder.CornerData('a', 'b', 'c', 'd', 'e')
      self.assertEqual(cd.corner_index, 'a')
      self.assertEqual(cd.corner_location, 'b')
      self.assertEqual(cd.brightness_score, 'c')
      self.assertEqual(cd.line1, 'd')
      self.assertEqual(cd.line2, 'e')
      cd_list = []
      cd_list.append(self.ScreenFinder.CornerData(0, None, None, None, None))
      cd_list.append(self.ScreenFinder.CornerData(3, None, None, None, None))
      cd_list.append(self.ScreenFinder.CornerData(1, None, None, None, None))
      cd_list.append(self.ScreenFinder.CornerData(2, None, None, None, None))
      cd_list.sort()
      for i in range(len(cd_list)):
        self.assertEqual(i, cd_list[i].corner_index)

    def testFindCorners(self):
      # TODO: Probably easier to just do end to end tests.
      pass

    def testDeDupCorners(self):
      sf = self._GetScreenFinder(None)
      data = []
      lines = []
      lines.append(np.asfarray((0, 1001, 0, -1)))
      lines.append(np.asfarray((-1, 0, 1001, 0)))
      lines.append(np.asfarray((1000, 1001, 1000, -1)))
      lines.append(np.asfarray((-1, 1000, 1001, 1000)))
      lines.append(np.asfarray((0, 10, 10, 0)))
      lines.append(np.asfarray((-1, 1001, 1001, 1001)))
      corners = np.asfarray(((1000, 1000), (0, 1000), (0, 0),
                             (1000, 0), (0, 10), (10, 0), (1000, 1001)))
      data.append(self.ScreenFinder.CornerData(2, corners[2], 100,
                                               lines[0], lines[1]))
      data.append(self.ScreenFinder.CornerData(1, corners[1], 100,
                                               lines[0], lines[3]))
      data.append(self.ScreenFinder.CornerData(3, corners[3], 100,
                                               lines[1], lines[2]))
      data.append(self.ScreenFinder.CornerData(0, corners[0], 100,
                                               lines[2], lines[3]))
      data.append(self.ScreenFinder.CornerData(2, corners[4], 120,
                                               lines[0], lines[4]))
      data.append(self.ScreenFinder.CornerData(2, corners[5], 110,
                                               lines[1], lines[4]))
      data.append(self.ScreenFinder.CornerData(0, corners[6], 110,
                                               lines[2], lines[5]))
      dedup = copy.copy(data)
      # Tests 2 non-duplicate corners, 1 corner with connected and unconnected
      # corners, and 1 corner with two connected corners.
      sf._DeDupCorners(dedup, corners)
      self.assertEqual(len(dedup), 4)
      self.assertIn(data[0], dedup)
      self.assertIn(data[1], dedup)
      self.assertIn(data[2], dedup)
      self.assertIn(data[6], dedup)

      # Same test, but this time the corner with connected and unconnected
      # corners now only contains unconnected corners.
      del data[0]
      corners = np.delete(corners, 2, axis=0)
      dedup2 = copy.copy(data)
      sf._DeDupCorners(dedup2, corners)
      self.assertEqual(len(dedup2), 4)
      self.assertIn(data[3], dedup2)
      self.assertIn(data[0], dedup2)
      self.assertIn(data[1], dedup2)
      self.assertIn(data[5], dedup2)

    def testFindExactCorners(self):
      sf = self._GetScreenFinder(None)
      img = np.zeros((3, 3), np.uint8)
      img[1][0] = 255
      img[0][1] = 255
      img[1][2] = 255
      img[2][1] = 255
      sf._frame_edges = img
      corners = np.asfarray([(1, 1), (1, 1), (1, 1), (1, 1)])
      expected = np.asfarray([(2, 0), (0, 0), (0, 2), (2, 2)])
      ret = sf._FindExactCorners(corners)
      np.testing.assert_equal(ret, expected)
      img2 = np.zeros((3, 3), np.uint8)
      img2[1][0] = 255
      img2[1][1] = 255
      img2[2][2] = 255
      img2[2][1] = 255
      sf._frame_edges = img2
      expected2 = [(2, 1), (0, 1), (0, 2), (2, 2)]
      ret2 = sf._FindExactCorners(corners)
      np.testing.assert_equal(ret2, expected2)

    def testSmoothCorners(self):
      sf = self._GetScreenFinder(None)
      corners = [[10, 10], [10, 10], [10, 10], [10, 10]]
      ret = sf._SmoothCorners(corners).tolist()
      self.assertListEqual(ret, corners)
      corners = [[0, 0], [0, 0], [0, 0], [0, 0]]
      expected = [[5, 5], [5, 5], [5, 5], [5, 5]]
      ret = sf._SmoothCorners(corners).tolist()
      self.assertListEqual(ret, expected)
      expected = [[2.5, 2.5], [2.5, 2.5], [2.5, 2.5], [2.5, 2.5]]
      ret = sf._SmoothCorners(corners).tolist()
      self.assertListEqual(ret, expected)

    def testGetTransform(self):
      sf = self._GetScreenFinder(None)
      corners = np.array([[100, 1000], [0, 1000], [0, 0], [100, 0]], np.float32)
      transform, w, h = sf._GetTransform(corners, 1)
      transform = np.round(transform, 2)
      expected = [[1., 0., 1.], [-0., -1., 1001.], [0., -0., 1.]]
      self.assertListEqual(transform.tolist(), expected)
      self.assertEqual(w, 102)
      self.assertEqual(h, 1002)

      corners = np.array([(200, 2000), (0, 2000), (0, 0), (200, 0)], np.float32)
      transform, w, h = sf._GetTransform(corners, 5)
      transform = np.round(transform, 2)
      expected = [[0.5, 0.0, 5.0], [-0.0, -0.5, 1005.0], [-0.0, 0.0, 1.0]]
      self.assertListEqual(transform.tolist(), expected)
      self.assertEqual(w, 110)
      self.assertEqual(h, 1010)

    def testNewScreenLocation(self):
      sf = self._GetScreenFinder(None)
      corners_2 = np.asfarray([[np.nan, np.nan], [0, 1000], [np.nan, np.nan],
                               [1000, 0]])
      corners_3 = np.asfarray([[1000, 1000], [0, 1000], [np.nan, np.nan],
                               [1000, 0]])
      corners_4 = np.asfarray([[1000, 1000], [0, 1000], [0, 0], [1000, 0]])
      lines = []
      # Box with corners at (0, 0), (1000, 0), (0, 1000), (1000, 1000)
      lines.append(np.asfarray(((0, 1001, 0, -1))))
      lines.append(np.asfarray(((-1, 0, 1001, 0))))
      lines.append(np.asfarray(((1000, 1001, 1000, -1))))
      lines.append(np.asfarray(((-1, 1000, 1001, 1000))))
      # Additional intersections near a corner.
      lines.append(np.asfarray(((0, 3, 7, 0))))
      lines.append(np.asfarray(((0, 4, 6, 0))))
      intersections = sf._FindIntersections(lines)
      failed = False
      try:
        sf._NewScreenLocation(corners_3, 1, intersections)
      except self.ScreenFinder.ScreenNotFoundError:
        failed = True
      self.assertTrue(failed)

      sf._lost_corner_frames = 10
      sf._lost_corners = [True, True, True, True]
      ret = sf._NewScreenLocation(corners_4, 0, intersections)
      np.testing.assert_equal(ret, corners_4)
      self.assertListEqual(sf._lost_corners, [False, False, False, False])
      self.assertEqual(sf._lost_corner_frames, 0)

      sf._prev_corners = corners_4
      ret = sf._NewScreenLocation(corners_3, 1, intersections)
      ret = np.round(ret)
      np.testing.assert_equal(ret, corners_4)
      self.assertListEqual(sf._lost_corners, [False, False, True, False])
      self.assertEqual(sf._lost_corner_frames, 1)

      sf._prev_corners = np.asfarray([(1000, 1000), (0, 1000),
                                      (0, 3), (1000, 0)])
      ret = sf._NewScreenLocation(corners_3, 1, intersections)
      ret = np.round(ret)
      np.testing.assert_equal(ret, corners_4)
      self.assertListEqual(sf._lost_corners, [False, False, True, False])
      self.assertEqual(sf._lost_corner_frames, 2)

      ret = sf._NewScreenLocation(corners_2, 2, intersections)
      ret = np.round(ret)
      expected = [[1000, 1000], [0, 1000], [0, 3], [1000, 0]]
      np.testing.assert_equal(ret, expected)
      self.assertListEqual(sf._lost_corners, [True, False, True, False])
      self.assertEqual(sf._lost_corner_frames, 3)
