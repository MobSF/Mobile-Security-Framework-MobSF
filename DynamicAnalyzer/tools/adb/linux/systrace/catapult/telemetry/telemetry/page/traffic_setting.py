# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

_Configs = collections.namedtuple(
  '_Configs', ('download_bandwidth_kbps,'
               'upload_bandwidth_kbps,'
               'round_trip_latency_ms'))

# These presets are copied from devtool's:
# https://cs.chromium.org/chromium/src/third_party/WebKit/Source/devtools/front_end/components/NetworkConditionsSelector.js?l=43
NONE = 'none'
GPRS = 'GPRS'
REGULAR_2G = 'Regular-2G'
GOOD_2G = 'Good-2G'
REGULAR_3G = 'Regular-3G'
GOOD_3G = 'Good-3G'
REGULAR_4G = 'Regular-4G'
DSL = 'DSL'
WIFI = 'WiFi'

NETWORK_CONFIGS = {
  NONE: _Configs(0, 0, 0),
  GPRS: _Configs(50 * 1024 / 8, 20 * 1024 / 8, 500),
  REGULAR_2G: _Configs(250 * 1024 / 8, 50 * 1024 / 8, 300),
  GOOD_2G: _Configs(450 * 1024 / 8, 150 * 1024 / 8, 150),
  REGULAR_3G: _Configs(750 * 1024 / 8, 250 * 1024 / 8, 100),
  GOOD_3G: _Configs(1.5 * 1024 * 1024 / 8, 750 * 1024 / 8, 40),
  REGULAR_4G: _Configs(4 * 1024 * 1024 / 8, 3 * 1024 * 1024 / 8, 20),
  DSL: _Configs(2 * 1024 * 1024 / 8, 1 * 1024 * 1024 / 8, 5),
  WIFI: _Configs(30 * 1024 * 1024 / 8, 15 * 1024 * 1024 / 8, 2),
}
