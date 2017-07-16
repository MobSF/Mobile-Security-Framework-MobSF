# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class _OptionalContextManager(object):

  def __init__(self, manager, condition):
    self._manager = manager
    self._condition = condition

  def __enter__(self):
    if self._condition:
      return self._manager.__enter__()
    return None

  def __exit__(self, exc_type, exc_val, exc_tb):
    if self._condition:
      return self._manager.__exit__(exc_type, exc_val, exc_tb)
    return None


def Optional(manager, condition):
  """Wraps the provided context manager and runs it if condition is True.

  Args:
    manager: A context manager to conditionally run.
    condition: If true, runs the given context manager.
  Returns:
    A context manager that conditionally executes the given manager.
  """
  return _OptionalContextManager(manager, condition)

