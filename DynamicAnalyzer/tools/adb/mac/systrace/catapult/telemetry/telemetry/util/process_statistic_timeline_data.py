# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class ProcessStatisticTimelineData(object):
  """Holds value of a stat for one or more processes.

  This object can hold a value for more than one pid by adding another
  object."""

  def __init__(self, pid, value):
    super(ProcessStatisticTimelineData, self).__init__()
    assert value >= 0
    self._value_by_pid = {pid: value}

  def __sub__(self, other):
    """The results of subtraction is an object holding only the pids contained
    in |self|.

    The motivation is that some processes may have died between two consecutive
    measurements. The desired behavior is to only make calculations based on
    the processes that are alive at the end of the second measurement."""
    # pylint: disable=protected-access
    ret = self.__class__(0, 0)
    my_dict = self._value_by_pid

    ret._value_by_pid = (
        {k: my_dict[k] - other._value_by_pid.get(k, 0) for
            k in my_dict.keys()})
    return ret

  def __add__(self, other):
    """The result contains pids from both |self| and |other|, if duplicate
    pids are found between objects, an error will occur. """
    # pylint: disable=protected-access
    intersecting_pids = (set(self._value_by_pid.keys()) &
        set(other._value_by_pid.keys()))
    assert len(intersecting_pids) == 0

    ret = self.__class__(0, 0)
    ret._value_by_pid = {}
    ret._value_by_pid.update(self._value_by_pid)
    ret._value_by_pid.update(other._value_by_pid)
    return ret

  @property
  def value_by_pid(self):
    return self._value_by_pid

  def total_sum(self):
    """Returns the sum of all values contained by this object. """
    return sum(self._value_by_pid.values())


class IdleWakeupTimelineData(ProcessStatisticTimelineData):
  """A ProcessStatisticTimelineData to hold idle wakeups."""
  pass
