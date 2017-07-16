# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import sys

def _JoinPath(*path_parts):
  return os.path.abspath(os.path.join(*path_parts))


def _AddDirToPythonPath(*path_parts):
  path = _JoinPath(*path_parts)
  if os.path.isdir(path) and path not in sys.path:
    # Some call sites that use Telemetry assume that sys.path[0] is the
    # directory containing the script, so we add these extra paths to right
    # after sys.path[0].
    sys.path.insert(1, path)

_CATAPULT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.path.pardir, os.path.pardir)

_AddDirToPythonPath(_CATAPULT_DIR, 'common', 'battor')
_AddDirToPythonPath(_CATAPULT_DIR, 'common', 'py_utils')
_AddDirToPythonPath(_CATAPULT_DIR, 'common', 'py_trace_event')
_AddDirToPythonPath(_CATAPULT_DIR, 'common', 'py_trace_event', 'py_trace_event')
_AddDirToPythonPath(_CATAPULT_DIR, 'devil')
_AddDirToPythonPath(_CATAPULT_DIR, 'systrace')
_AddDirToPythonPath(_CATAPULT_DIR, 'telemetry')
