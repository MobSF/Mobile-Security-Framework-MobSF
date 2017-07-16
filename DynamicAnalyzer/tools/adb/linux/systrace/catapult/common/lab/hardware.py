#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Query build slave hardware info, and print it to stdout as csv."""

import csv
import json
import logging
import sys
import urllib2


_MASTERS = [
    'chromium.perf',
    'chromium.perf.fyi',
    'client.catapult',
    'tryserver.chromium.perf',
    'tryserver.client.catapult',
]


_KEYS = [
    'master', 'builder', 'hostname',

    'os family', 'os version', 'bitness (userland)',

    'product name', 'architecture', 'processor count', 'processor type',
    'memory total',

    'facter version', 'git version', 'puppet version', 'python version',
    'ruby version',

    'android device 1', 'android device 2', 'android device 3',
    'android device 4', 'android device 5', 'android device 6',
    'android device 7', 'android device 8',
]
_EXCLUDED_KEYS = frozenset([
    'architecture (userland)',
    'b directory',
    'last puppet run',
    'uptime',
    'windows version',
])


def main():
  writer = csv.DictWriter(sys.stdout, _KEYS)
  writer.writeheader()

  for master_name in _MASTERS:
    master_data = json.load(urllib2.urlopen(
        'http://build.chromium.org/p/%s/json/slaves' % master_name))

    slaves = sorted(master_data.iteritems(),
                    key=lambda x: (x[1]['builders'].keys(), x[0]))
    for slave_name, slave_data in slaves:
      for builder_name in slave_data['builders']:
        row = {
            'master': master_name,
            'builder': builder_name,
            'hostname': slave_name,
        }

        host_data = slave_data['host']
        if host_data:
          host_data = host_data.splitlines()
          if len(host_data) > 1:
            for line in host_data:
              if not line:
                continue
              key, value = line.split(': ')
              if key in _EXCLUDED_KEYS:
                continue
              row[key] = value

        # Munge keys.
        row = {key.replace('_', ' '): value for key, value in row.iteritems()}
        if 'osfamily' in row:
          row['os family'] = row.pop('osfamily')
        if 'product name' not in row and slave_name.startswith('slave'):
          row['product name'] = 'Google Compute Engine'

        try:
          writer.writerow(row)
        except ValueError:
          logging.error(row)
          raise


if __name__ == '__main__':
  main()
