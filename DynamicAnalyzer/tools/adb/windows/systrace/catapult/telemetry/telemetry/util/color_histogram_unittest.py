# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.util import color_histogram
from telemetry.util import image_util
from telemetry.util import rgba_color

class HistogramDistanceTest(unittest.TestCase):
  def testNoData(self):
    hist1 = []
    hist2 = []
    self.assertEqual(color_histogram.HistogramDistance(hist1, hist2), 0)

    hist1 = [0, 0, 0]
    hist2 = [0, 0, 0]
    self.assertRaises(
        ValueError, lambda: color_histogram.HistogramDistance(hist1, hist2))

  def testWrongSizes(self):
    hist1 = [1]
    hist2 = [1, 0]
    self.assertRaises(
        ValueError, lambda: color_histogram.HistogramDistance(hist1, hist2))

  def testNoDistance(self):
    hist1 = [2, 4, 1, 8, 0, 0]
    hist2 = [2, 4, 1, 8, 0, 0]
    self.assertEqual(color_histogram.HistogramDistance(hist1, hist2), 0)

  def testNormalizeCounts(self):
    hist1 = [0, 0, 1, 0, 0]
    hist2 = [0, 0, 0, 0, 7]
    self.assertEqual(color_histogram.HistogramDistance(hist1, hist2), 2)
    self.assertEqual(color_histogram.HistogramDistance(hist2, hist1), 2)

  def testDistance(self):
    hist1 = [2, 0, 1, 3, 4]
    hist2 = [3, 1, 2, 4, 0]
    self.assertEqual(color_histogram.HistogramDistance(hist1, hist2), 1)
    self.assertEqual(color_histogram.HistogramDistance(hist2, hist1), 1)

    hist1 = [0, 1, 3, 1]
    hist2 = [2, 2, 1, 0]
    self.assertEqual(color_histogram.HistogramDistance(hist1, hist2), 1.2)
    self.assertEqual(color_histogram.HistogramDistance(hist2, hist1), 1.2)


class HistogramTest(unittest.TestCase):
  def testHistogram(self):
    pixels = [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3,
              1, 2, 3, 8, 7, 6, 5, 4, 6, 1, 2, 3,
              1, 2, 3, 8, 7, 6, 5, 4, 6, 1, 2, 3]
    bmp = image_util.FromRGBPixels(4, 3, pixels)
    bmp = image_util.Crop(bmp, 1, 1, 2, 2)

    hist = image_util.GetColorHistogram(bmp)
    for i in xrange(3):
      self.assertEquals(sum(hist[i]),
                        image_util.Width(bmp) * image_util.Height(bmp))
    self.assertEquals(hist.r[1], 0)
    self.assertEquals(hist.r[5], 2)
    self.assertEquals(hist.r[8], 2)
    self.assertEquals(hist.g[2], 0)
    self.assertEquals(hist.g[4], 2)
    self.assertEquals(hist.g[7], 2)
    self.assertEquals(hist.b[3], 0)
    self.assertEquals(hist.b[6], 4)

  def testHistogramIgnoreColor(self):
    pixels = [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3,
              1, 2, 3, 8, 7, 6, 5, 4, 6, 1, 2, 3,
              1, 2, 3, 8, 7, 6, 5, 4, 6, 1, 2, 3]
    bmp = image_util.FromRGBPixels(4, 3, pixels)

    hist = image_util.GetColorHistogram(
        bmp, ignore_color=rgba_color.RgbaColor(1, 2, 3))
    self.assertEquals(hist.r[1], 0)
    self.assertEquals(hist.r[5], 2)
    self.assertEquals(hist.r[8], 2)
    self.assertEquals(hist.g[2], 0)
    self.assertEquals(hist.g[4], 2)
    self.assertEquals(hist.g[7], 2)
    self.assertEquals(hist.b[3], 0)
    self.assertEquals(hist.b[6], 4)

  def testHistogramIgnoreColorTolerance(self):
    pixels = [1, 2, 3, 4, 5, 6,
              7, 8, 9, 8, 7, 6]
    bmp = image_util.FromRGBPixels(2, 2, pixels)

    hist = image_util.GetColorHistogram(
        bmp, ignore_color=rgba_color.RgbaColor(0, 1, 2), tolerance=1)
    self.assertEquals(hist.r[1], 0)
    self.assertEquals(hist.r[4], 1)
    self.assertEquals(hist.r[7], 1)
    self.assertEquals(hist.r[8], 1)
    self.assertEquals(hist.g[2], 0)
    self.assertEquals(hist.g[5], 1)
    self.assertEquals(hist.g[7], 1)
    self.assertEquals(hist.g[8], 1)
    self.assertEquals(hist.b[3], 0)
    self.assertEquals(hist.b[6], 2)
    self.assertEquals(hist.b[9], 1)

  def testHistogramDistanceIgnoreColor(self):
    pixels = [1, 2, 3, 1, 2, 3,
              1, 2, 3, 1, 2, 3]
    bmp = image_util.FromRGBPixels(2, 2, pixels)

    hist1 = image_util.GetColorHistogram(
        bmp, ignore_color=rgba_color.RgbaColor(1, 2, 3))
    hist2 = image_util.GetColorHistogram(bmp)

    self.assertEquals(hist1.Distance(hist2), 0)
