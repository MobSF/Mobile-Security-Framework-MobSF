# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import types

from py_trace_event.trace_event_impl import decorators


class TracedMetaClass(type):
  def __new__(cls, name, bases, attrs):
    for attr_name, attr_value in attrs.iteritems():
      if isinstance(attr_value, types.FunctionType):
        attrs[attr_name] = decorators.traced(attr_value)

    return super(TracedMetaClass, cls).__new__(cls, name, bases, attrs)
