# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Utility functions used to generate info used by the bots.

TODO(eyaich): Remove once we no longer generate the list of benchmarks to
run on the perf waterfall in telemetry.
"""

import hashlib

def GetDeviceAffinity(num_shards, base_name):
  # Based on the current timings, we shift the result of the hash function to
  # achieve better load balancing. Those shift values are to be revised when
  # necessary. The shift value is calculated such that the total cycle time
  # is minimized.
  hash_shift = {
    2 : 47,  # for old desktop configurations with 2 slaves
    5 : 56,  # for new desktop configurations with 5 slaves
    21 : 43  # for Android 3 slaves 7 devices configurations
  }
  shift = hash_shift.get(num_shards, 0)
  base_name_hash = hashlib.sha1(base_name).hexdigest()
  device_affinity = (int(base_name_hash, 16) >> shift) % num_shards
  return device_affinity
