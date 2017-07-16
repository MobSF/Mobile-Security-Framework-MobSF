# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Color Histograms and implementations of functions operating on them."""

from __future__ import division

import collections

from telemetry.internal.util import external_modules

np = external_modules.ImportOptionalModule('numpy')


def HistogramDistance(hist1, hist2, default_color=None):
  """Earth mover's distance.
  http://en.wikipedia.org/wiki/Earth_mover's_distance"""
  if len(hist1) != len(hist2):
    raise ValueError('Trying to compare histograms '
                     'of different sizes, %s != %s' % (len(hist1), len(hist2)))
  if len(hist1) == 0:
    return 0

  sum_func = np.sum if np is not None else sum

  n1 = sum_func(hist1)
  n2 = sum_func(hist2)
  if (n1 == 0 or n2 == 0) and default_color is None:
    raise ValueError('Histogram has no data and no default color.')
  if n1 == 0:
    hist1[default_color] = 1
    n1 = 1
  if n2 == 0:
    hist2[default_color] = 1
    n2 = 1

  if np is not None:
    remainder = np.multiply(hist1, n2) - np.multiply(hist2, n1)
    cumsum = np.cumsum(remainder)
    total = np.sum(np.abs(cumsum))
  else:
    total = 0
    remainder = 0
    for value1, value2 in zip(hist1, hist2):
      remainder += value1 * n2 - value2 * n1
      total += abs(remainder)
    assert remainder == 0, (
        '%s pixel(s) left over after computing histogram distance.'
        % abs(remainder))
  return abs(float(total) / n1 / n2)


class ColorHistogram(
    collections.namedtuple('ColorHistogram', ['r', 'g', 'b', 'default_color'])):
  # pylint: disable=no-init
  # pylint: disable=super-on-old-class

  def __new__(cls, r, g, b, default_color=None):
    return super(ColorHistogram, cls).__new__(cls, r, g, b, default_color)

  def Distance(self, other):
    total = 0
    for i in xrange(3):
      default_color = self[3][i] if self[3] is not None else None
      total += HistogramDistance(self[i], other[i], default_color)
    return total
