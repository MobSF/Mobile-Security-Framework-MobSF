# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import inspect


def IsDirectlyConstructable(cls):
  """Returns True if instance of |cls| can be construct without arguments."""
  assert inspect.isclass(cls)
  if not hasattr(cls, '__init__'):
    # Case |class A: pass|.
    return True
  if cls.__init__ is object.__init__:
    # Case |class A(object): pass|.
    return True
  # Case |class (object):| with |__init__| other than |object.__init__|.
  args, _, _, defaults = inspect.getargspec(cls.__init__)
  if defaults is None:
    defaults = ()
  # Return true if |self| is only arg without a default.
  return len(args) == len(defaults) + 1
