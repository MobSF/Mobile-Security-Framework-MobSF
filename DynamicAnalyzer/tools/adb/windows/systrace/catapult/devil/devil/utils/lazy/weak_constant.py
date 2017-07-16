# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import threading


class WeakConstant(object):
  """A thread-safe, lazily initialized object.

  This does not support modification after initialization. The intended
  constant nature of the object is not enforced, though, hence the "weak".
  """

  def __init__(self, initializer):
    self._initialized = False
    self._initializer = initializer
    self._lock = threading.Lock()
    self._val = None

  def read(self):
    """Get the object, creating it if necessary."""
    if self._initialized:
      return self._val
    with self._lock:
      if not self._initialized:
        self._val = self._initializer()
        self._initialized = True
    return self._val
