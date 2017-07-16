# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import atexit
import logging

def _WrapFunction(function):
  def _wrapped_function(*args, **kwargs):
    logging.debug('Try running %s', repr(function))
    function(*args, **kwargs)
    logging.debug('Did run %s', repr(function))
  return _wrapped_function

def Register(function, *args, **kwargs):
  atexit.register(_WrapFunction(function), *args, **kwargs)
