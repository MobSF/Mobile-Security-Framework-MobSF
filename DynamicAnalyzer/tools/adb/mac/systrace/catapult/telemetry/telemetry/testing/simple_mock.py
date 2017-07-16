# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A very very simple mock object harness."""

DONT_CARE = ''

class MockFunctionCall(object):
  def __init__(self, name):
    self.name = name
    self.args = tuple()
    self.return_value = None
    self.when_called_handlers = []

  def WithArgs(self, *args):
    self.args = args
    return self

  def WillReturn(self, value):
    self.return_value = value
    return self

  def WhenCalled(self, handler):
    self.when_called_handlers.append(handler)

  def VerifyEquals(self, got):
    if self.name != got.name:
      raise Exception('Self %s, got %s' % (repr(self), repr(got)))
    if len(self.args) != len(got.args):
      raise Exception('Self %s, got %s' % (repr(self), repr(got)))
    for i in range(len(self.args)):
      self_a = self.args[i]
      got_a = got.args[i]
      if self_a == DONT_CARE:
        continue
      if self_a != got_a:
        raise Exception('Self %s, got %s' % (repr(self), repr(got)))

  def __repr__(self):
    def arg_to_text(a):
      if a == DONT_CARE:
        return '_'
      return repr(a)
    args_text = ', '.join([arg_to_text(a) for a in self.args])
    if self.return_value in (None, DONT_CARE):
      return '%s(%s)' % (self.name, args_text)
    return '%s(%s)->%s' % (self.name, args_text, repr(self.return_value))

class MockTrace(object):
  def __init__(self):
    self.expected_calls = []
    self.next_call_index = 0

class MockObject(object):
  def __init__(self, parent_mock=None):
    if parent_mock:
      self._trace = parent_mock._trace # pylint: disable=protected-access
    else:
      self._trace = MockTrace()

  def __setattr__(self, name, value):
    if (not hasattr(self, '_trace') or
        hasattr(value, 'is_hook')):
      object.__setattr__(self, name, value)
      return
    assert isinstance(value, MockObject)
    object.__setattr__(self, name, value)

  def SetAttribute(self, name, value):
    setattr(self, name, value)

  def ExpectCall(self, func_name, *args):
    assert self._trace.next_call_index == 0
    if not hasattr(self, func_name):
      self._install_hook(func_name)

    call = MockFunctionCall(func_name)
    self._trace.expected_calls.append(call)
    call.WithArgs(*args)
    return call

  def _install_hook(self, func_name):
    def handler(*args, **_):
      got_call = MockFunctionCall(
        func_name).WithArgs(*args).WillReturn(DONT_CARE)
      if self._trace.next_call_index >= len(self._trace.expected_calls):
        raise Exception(
          'Call to %s was not expected, at end of programmed trace.' %
          repr(got_call))
      expected_call = self._trace.expected_calls[
        self._trace.next_call_index]
      expected_call.VerifyEquals(got_call)
      self._trace.next_call_index += 1
      for h in expected_call.when_called_handlers:
        h(*args)
      return expected_call.return_value
    handler.is_hook = True
    setattr(self, func_name, handler)
