#!/usr/bin/env python
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Defines a list of common network speeds.

These values come from http://www.webpagetest.org/

See:
https://sites.google.com/a/webpagetest.org/docs/other-resources/2011-fcc-broadband-data
https://github.com/WPO-Foundation/webpagetest/blob/HEAD/www/settings/connectivity.ini.sample
"""

import collections


NetConfig = collections.namedtuple('NetConfig', ['down', 'up', 'delay_ms'])


# pylint: disable=bad-whitespace
_NET_CONFIGS = {
    'dialup': NetConfig(down=   '49Kbit/s', up=  '30Kbit/s', delay_ms= '120'),
    '3g':     NetConfig(down= '1638Kbit/s', up= '768Kbit/s', delay_ms= '150'),
    'dsl':    NetConfig(down= '1536Kbit/s', up= '384Kbit/s', delay_ms=  '50'),
    'cable':  NetConfig(down=    '5Mbit/s', up=   '1Mbit/s', delay_ms=  '28'),
    'fios':   NetConfig(down=   '20Mbit/s', up=   '5Mbit/s', delay_ms=   '4'),
    }


NET_CONFIG_NAMES = _NET_CONFIGS.keys()


def GetNetConfig(key):
  """Returns the NetConfig object corresponding to the given |key|."""
  if key not in _NET_CONFIGS:
    raise KeyError('No net config with key: %s' % key)
  return _NET_CONFIGS[key]
