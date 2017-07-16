# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A dummy exception subclass used by core/discover.py's unit tests."""

class DummyException(Exception):
  def __init__(self):
    super(DummyException, self).__init__()
