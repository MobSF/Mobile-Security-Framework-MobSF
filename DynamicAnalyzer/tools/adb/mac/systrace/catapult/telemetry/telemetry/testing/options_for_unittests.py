# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module provides the global variable options_for_unittests.

This is set to a BrowserOptions object by the test harness, or None
if unit tests are not running.

This allows multiple unit tests to use a specific
browser, in face of multiple options."""


_options = []


def Push(options):
  _options.append(options)


def Pop():
  return _options.pop()


def GetCopy():
  if not AreSet():
    return None
  return _options[-1].Copy()


def AreSet():
  return bool(_options)
