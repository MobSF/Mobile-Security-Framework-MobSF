# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=protected-access


class OSVersion(str):
  def __new__(cls, friendly_name, sortable_name):
    version = str.__new__(cls, friendly_name)
    version._sortable_name = sortable_name
    return version

  def __lt__(self, other):
    return self._sortable_name < other._sortable_name

  def __gt__(self, other):
    return self._sortable_name > other._sortable_name

  def __le__(self, other):
    return self._sortable_name <= other._sortable_name

  def __ge__(self, other):
    return self._sortable_name >= other._sortable_name


XP = OSVersion('xp', 5.1)
VISTA = OSVersion('vista', 6.0)
WIN7 = OSVersion('win7', 6.1)
WIN8 = OSVersion('win8', 6.2)
WIN81 = OSVersion('win8.1', 6.3)
WIN10 = OSVersion('win10', 10)

LEOPARD = OSVersion('leopard', 105)
SNOWLEOPARD = OSVersion('snowleopard', 106)
LION = OSVersion('lion', 107)
MOUNTAINLION = OSVersion('mountainlion', 108)
MAVERICKS = OSVersion('mavericks', 109)
YOSEMITE = OSVersion('yosemite', 1010)
ELCAPITAN = OSVersion('elcapitan', 1011)
SIERRA = OSVersion('sierra', 1012)
