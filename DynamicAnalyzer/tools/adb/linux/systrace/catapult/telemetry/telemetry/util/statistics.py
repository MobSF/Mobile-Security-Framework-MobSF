# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A collection of statistical utility functions to be used by metrics."""

import math


def Clamp(value, low=0.0, high=1.0):
  """Clamp a value between some low and high value."""
  return min(max(value, low), high)


def NormalizeSamples(samples):
  """Sorts the samples, and map them linearly to the range [0,1].

  They're mapped such that for the N samples, the first sample is 0.5/N and the
  last sample is (N-0.5)/N.

  Background: The discrepancy of the sample set i/(N-1); i=0, ..., N-1 is 2/N,
  twice the discrepancy of the sample set (i+1/2)/N; i=0, ..., N-1. In our case
  we don't want to distinguish between these two cases, as our original domain
  is not bounded (it is for Monte Carlo integration, where discrepancy was
  first used).
  """
  if not samples:
    return samples, 1.0
  samples = sorted(samples)
  low = min(samples)
  high = max(samples)
  new_low = 0.5 / len(samples)
  new_high = (len(samples)-0.5) / len(samples)
  if high-low == 0.0:
    return [0.5] * len(samples), 1.0
  scale = (new_high - new_low) / (high - low)
  for i in xrange(0, len(samples)):
    samples[i] = float(samples[i] - low) * scale + new_low
  return samples, scale


def Discrepancy(samples, location_count=None):
  """Computes the discrepancy of a set of 1D samples from the interval [0,1].

  The samples must be sorted. We define the discrepancy of an empty set
  of samples to be zero.

  http://en.wikipedia.org/wiki/Low-discrepancy_sequence
  http://mathworld.wolfram.com/Discrepancy.html
  """
  if not samples:
    return 0.0

  max_local_discrepancy = 0
  inv_sample_count = 1.0 / len(samples)
  locations = []
  # For each location, stores the number of samples less than that location.
  count_less = []
  # For each location, stores the number of samples less than or equal to that
  # location.
  count_less_equal = []

  if location_count:
    # Generate list of equally spaced locations.
    sample_index = 0
    for i in xrange(0, int(location_count)):
      location = float(i) / (location_count-1)
      locations.append(location)
      while sample_index < len(samples) and samples[sample_index] < location:
        sample_index += 1
      count_less.append(sample_index)
      while  sample_index < len(samples) and samples[sample_index] <= location:
        sample_index += 1
      count_less_equal.append(sample_index)
  else:
    # Populate locations with sample positions. Append 0 and 1 if necessary.
    if samples[0] > 0.0:
      locations.append(0.0)
      count_less.append(0)
      count_less_equal.append(0)
    for i in xrange(0, len(samples)):
      locations.append(samples[i])
      count_less.append(i)
      count_less_equal.append(i+1)
    if samples[-1] < 1.0:
      locations.append(1.0)
      count_less.append(len(samples))
      count_less_equal.append(len(samples))

  # Compute discrepancy as max(overshoot, -undershoot), where
  # overshoot = max(count_closed(i, j)/N - length(i, j)) for all i < j,
  # undershoot = min(count_open(i, j)/N - length(i, j)) for all i < j,
  # N = len(samples),
  # count_closed(i, j) is the number of points between i and j including ends,
  # count_open(i, j) is the number of points between i and j excluding ends,
  # length(i, j) is locations[i] - locations[j].

  # The following algorithm is modification of Kadane's algorithm,
  # see https://en.wikipedia.org/wiki/Maximum_subarray_problem.

  # The maximum of (count_closed(k, i-1)/N - length(k, i-1)) for any k < i-1.
  max_diff = 0
  # The minimum of (count_open(k, i-1)/N - length(k, i-1)) for any k < i-1.
  min_diff = 0
  for i in xrange(1, len(locations)):
    length = locations[i] - locations[i - 1]
    count_closed = count_less_equal[i] - count_less[i - 1]
    count_open = count_less[i] - count_less_equal[i - 1]
    # Number of points that are added if we extend a closed range that
    # ends at location (i-1).
    count_closed_increment = count_less_equal[i] - count_less_equal[i - 1]
    # Number of points that are added if we extend an open range that
    # ends at location (i-1).
    count_open_increment = count_less[i] - count_less[i - 1]

    # Either extend the previous optimal range or start a new one.
    max_diff = max(
        float(count_closed_increment) * inv_sample_count - length + max_diff,
        float(count_closed) * inv_sample_count - length)
    min_diff = min(
        float(count_open_increment) * inv_sample_count - length + min_diff,
        float(count_open) * inv_sample_count - length)

    max_local_discrepancy = max(max_diff, -min_diff, max_local_discrepancy)
  return max_local_discrepancy


def TimestampsDiscrepancy(timestamps, absolute=True,
                          location_count=None):
  """A discrepancy based metric for measuring timestamp jank.

  TimestampsDiscrepancy quantifies the largest area of jank observed in a series
  of timestamps.  Note that this is different from metrics based on the
  max_time_interval. For example, the time stamp series A = [0,1,2,3,5,6] and
  B = [0,1,2,3,5,7] have the same max_time_interval = 2, but
  Discrepancy(B) > Discrepancy(A).

  Two variants of discrepancy can be computed:

  Relative discrepancy is following the original definition of
  discrepancy. It characterized the largest area of jank, relative to the
  duration of the entire time stamp series.  We normalize the raw results,
  because the best case discrepancy for a set of N samples is 1/N (for
  equally spaced samples), and we want our metric to report 0.0 in that
  case.

  Absolute discrepancy also characterizes the largest area of jank, but its
  value wouldn't change (except for imprecisions due to a low
  |interval_multiplier|) if additional 'good' intervals were added to an
  exisiting list of time stamps.  Its range is [0,inf] and the unit is
  milliseconds.

  The time stamp series C = [0,2,3,4] and D = [0,2,3,4,5] have the same
  absolute discrepancy, but D has lower relative discrepancy than C.

  |timestamps| may be a list of lists S = [S_1, S_2, ..., S_N], where each
  S_i is a time stamp series. In that case, the discrepancy D(S) is:
  D(S) = max(D(S_1), D(S_2), ..., D(S_N))
  """
  if not timestamps:
    return 0.0

  if isinstance(timestamps[0], list):
    range_discrepancies = [TimestampsDiscrepancy(r) for r in timestamps]
    return max(range_discrepancies)

  samples, sample_scale = NormalizeSamples(timestamps)
  discrepancy = Discrepancy(samples, location_count)
  inv_sample_count = 1.0 / len(samples)
  if absolute:
    # Compute absolute discrepancy
    discrepancy /= sample_scale
  else:
    # Compute relative discrepancy
    discrepancy = Clamp((discrepancy-inv_sample_count) / (1.0-inv_sample_count))
  return discrepancy


def DurationsDiscrepancy(durations, absolute=True,
                         location_count=None):
  """A discrepancy based metric for measuring duration jank.

  DurationsDiscrepancy computes a jank metric which measures how irregular a
  given sequence of intervals is. In order to minimize jank, each duration
  should be equally long. This is similar to how timestamp jank works,
  and we therefore reuse the timestamp discrepancy function above to compute a
  similar duration discrepancy number.

  Because timestamp discrepancy is defined in terms of timestamps, we first
  convert the list of durations to monotonically increasing timestamps.

  Args:
    durations: List of interval lengths in milliseconds.
    absolute: See TimestampsDiscrepancy.
    interval_multiplier: See TimestampsDiscrepancy.
  """
  if not durations:
    return 0.0

  timestamps = reduce(lambda x, y: x + [x[-1] + y], durations, [0])
  return TimestampsDiscrepancy(timestamps, absolute, location_count)


def ArithmeticMean(data):
  """Calculates arithmetic mean.

  Args:
    data: A list of samples.

  Returns:
    The arithmetic mean value, or 0 if the list is empty.
  """
  numerator_total = Total(data)
  denominator_total = Total(len(data))
  return DivideIfPossibleOrZero(numerator_total, denominator_total)


def StandardDeviation(data):
  """Calculates the standard deviation.

  Args:
    data: A list of samples.

  Returns:
    The standard deviation of the samples provided.
  """
  if len(data) == 1:
    return 0.0

  mean = ArithmeticMean(data)
  variances = [float(x) - mean for x in data]
  variances = [x * x for x in variances]
  std_dev = math.sqrt(ArithmeticMean(variances))

  return std_dev


def TrapezoidalRule(data, dx):
  """ Calculate the integral according to the trapezoidal rule

  TrapezoidalRule approximates the definite integral of f from a to b by
  the composite trapezoidal rule, using n subintervals.
  http://en.wikipedia.org/wiki/Trapezoidal_rule#Uniform_grid

  Args:
    data: A list of samples
    dx: The uniform distance along the x axis between any two samples

  Returns:
    The area under the curve defined by the samples and the uniform distance
    according to the trapezoidal rule.
  """

  n = len(data) - 1
  s = data[0] + data[n]

  if n == 0:
    return 0.0

  for i in range(1, n):
    s += 2 * data[i]

  return s * dx / 2.0

def Total(data):
  """Returns the float value of a number or the sum of a list."""
  if type(data) == float:
    total = data
  elif type(data) == int:
    total = float(data)
  elif type(data) == list:
    total = float(sum(data))
  else:
    raise TypeError
  return total


def DivideIfPossibleOrZero(numerator, denominator):
  """Returns the quotient, or zero if the denominator is zero."""
  return (float(numerator) / float(denominator)) if denominator else 0


def GeneralizedMean(values, exponent):
  """See http://en.wikipedia.org/wiki/Generalized_mean"""
  if not values:
    return 0.0
  sum_of_powers = 0.0
  for v in values:
    sum_of_powers += v ** exponent
  return (sum_of_powers / len(values)) ** (1.0/exponent)


def Median(values):
  """Gets the median of a list of values."""
  return Percentile(values, 50)


def Percentile(values, percentile):
  """Calculates the value below which a given percentage of values fall.

  For example, if 17% of the values are less than 5.0, then 5.0 is the 17th
  percentile for this set of values. When the percentage doesn't exactly
  match a rank in the list of values, the percentile is computed using linear
  interpolation between closest ranks.

  Args:
    values: A list of numerical values.
    percentile: A number between 0 and 100.

  Returns:
    The Nth percentile for the list of values, where N is the given percentage.
  """
  if not values:
    return 0.0
  sorted_values = sorted(values)
  n = len(values)
  percentile /= 100.0
  if percentile <= 0.5 / n:
    return sorted_values[0]
  elif percentile >= (n - 0.5) / n:
    return sorted_values[-1]
  else:
    floor_index = int(math.floor(n * percentile -  0.5))
    floor_value = sorted_values[floor_index]
    ceil_value = sorted_values[floor_index+1]
    alpha = n * percentile - 0.5 - floor_index
    return floor_value + alpha * (ceil_value - floor_value)


def GeometricMean(values):
  """Compute a rounded geometric mean from an array of values."""
  if not values:
    return None
  # To avoid infinite value errors, make sure no value is less than 0.001.
  new_values = []
  for value in values:
    if value > 0.001:
      new_values.append(value)
    else:
      new_values.append(0.001)
  # Compute the sum of the log of the values.
  log_sum = sum(map(math.log, new_values))
  # Raise e to that sum over the number of values.
  mean = math.pow(math.e, (log_sum / len(new_values)))
  # Return the rounded mean.
  return int(round(mean))
