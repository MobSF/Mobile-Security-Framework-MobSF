# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class Device(object):
  """ A base class of devices.
  A device instance contains all the necessary information for constructing
  a platform backend object for remote platforms.

  Attributes:
    name: A device name string in human-understandable term.
    guid: A unique id of the device. Subclass of device must specify this
      id properly so that device objects to a same actual device must have same
      guid.
    """

  def __init__(self, name, guid):
    self._name = name
    self._guid = guid

  @property
  def name(self):
    return self._name

  @property
  def guid(self):
    return self._guid

  @classmethod
  def GetAllConnectedDevices(cls, blacklist):
    raise NotImplementedError()
