# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Style-preserving Python code transforms.

This module provides components for modifying and querying Python code. They can
be used to build custom refactorings and linters.
"""

import functools
import multiprocessing

# pylint: disable=wildcard-import
from py_utils.refactor.annotated_symbol import *
from py_utils.refactor.module import Module


def _TransformFile(transform, file_path):
  module = Module(file_path)
  result = transform(module)
  module.Write()
  return result


def Transform(transform, file_paths):
  transform = functools.partial(_TransformFile, transform)
  return multiprocessing.Pool().map(transform, file_paths)
