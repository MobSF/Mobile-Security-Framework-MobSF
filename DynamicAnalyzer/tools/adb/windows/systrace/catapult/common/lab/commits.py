#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Print statistics about the rate of commits to a repository."""

import datetime
import itertools
import json
import math
import urllib
import urllib2


_BASE_URL = 'https://chromium.googlesource.com/'
# Can be up to 10,000.
_REVISION_COUNT = 1000

_REPOSITORIES = [
    'chromium/src',
    'angle/angle',
    'skia',
    'v8/v8',
]


def Pairwise(iterable):
  """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
  a, b = itertools.tee(iterable)
  next(b, None)
  return itertools.izip(a, b)


def Percentile(data, percentile):
  """Find a percentile of a list of values.

  Parameters:
    data: A sorted list of values.
    percentile: The percentile to look up, from 0.0 to 1.0.

  Returns:
    The percentile.

  Raises:
    ValueError: If data is empty.
  """
  if not data:
    raise ValueError()

  k = (len(data) - 1) * percentile
  f = math.floor(k)
  c = math.ceil(k)

  if f == c:
    return data[int(k)]
  return data[int(f)] * (c - k) + data[int(c)] * (k - f)


def CommitTimes(repository, revision_count):
  parameters = urllib.urlencode((('n', revision_count), ('format', 'JSON')))
  url = '%s/%s/+log?%s' % (_BASE_URL, urllib.quote(repository), parameters)
  data = json.loads(''.join(urllib2.urlopen(url).read().splitlines()[1:]))

  commit_times = []
  for revision in data['log']:
    commit_time_string = revision['committer']['time']
    commit_time = datetime.datetime.strptime(
        commit_time_string, '%a %b %d %H:%M:%S %Y')
    commit_times.append(commit_time)

  return commit_times


def main():
  for repository in _REPOSITORIES:
    commit_times = CommitTimes(repository, _REVISION_COUNT)

    commit_durations = []
    for time1, time2 in Pairwise(commit_times):
      commit_durations.append((time1 - time2).total_seconds())
    commit_durations.sort()

    print 'REPOSITORY:', repository
    print 'Start Date:', min(commit_times)
    print '  End Date:', max(commit_times)
    print '  Duration:', max(commit_times) - min(commit_times)
    print '         n:', len(commit_times)

    for p in (0.00, 0.05, 0.25, 0.50, 0.75, 0.95, 1.00):
      percentile = Percentile(commit_durations, p)
      print '%3d%% commit duration:' % (p * 100), '%6ds' % percentile
    mean = math.fsum(commit_durations) / len(commit_durations)
    print ' Min commit duration:', '%6ds' % min(commit_durations)
    print 'Mean commit duration:', '%6ds' % mean
    print ' Max commit duration:', '%6ds' % max(commit_durations)
    print


if __name__ == '__main__':
  main()
