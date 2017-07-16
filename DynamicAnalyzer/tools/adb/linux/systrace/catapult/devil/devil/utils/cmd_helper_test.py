#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for the cmd_helper module."""

import unittest
import subprocess
import time

from devil import devil_env
from devil.utils import cmd_helper

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


class CmdHelperSingleQuoteTest(unittest.TestCase):

  def testSingleQuote_basic(self):
    self.assertEquals('hello',
                      cmd_helper.SingleQuote('hello'))

  def testSingleQuote_withSpaces(self):
    self.assertEquals("'hello world'",
                      cmd_helper.SingleQuote('hello world'))

  def testSingleQuote_withUnsafeChars(self):
    self.assertEquals("""'hello'"'"'; rm -rf /'""",
                      cmd_helper.SingleQuote("hello'; rm -rf /"))

  def testSingleQuote_dontExpand(self):
    test_string = 'hello $TEST_VAR'
    cmd = 'TEST_VAR=world; echo %s' % cmd_helper.SingleQuote(test_string)
    self.assertEquals(test_string,
                      cmd_helper.GetCmdOutput(cmd, shell=True).rstrip())


class CmdHelperDoubleQuoteTest(unittest.TestCase):

  def testDoubleQuote_basic(self):
    self.assertEquals('hello',
                      cmd_helper.DoubleQuote('hello'))

  def testDoubleQuote_withSpaces(self):
    self.assertEquals('"hello world"',
                      cmd_helper.DoubleQuote('hello world'))

  def testDoubleQuote_withUnsafeChars(self):
    self.assertEquals('''"hello\\"; rm -rf /"''',
                      cmd_helper.DoubleQuote('hello"; rm -rf /'))

  def testSingleQuote_doExpand(self):
    test_string = 'hello $TEST_VAR'
    cmd = 'TEST_VAR=world; echo %s' % cmd_helper.DoubleQuote(test_string)
    self.assertEquals('hello world',
                      cmd_helper.GetCmdOutput(cmd, shell=True).rstrip())


class CmdHelperShinkToSnippetTest(unittest.TestCase):

  def testShrinkToSnippet_noArgs(self):
    self.assertEquals('foo',
        cmd_helper.ShrinkToSnippet(['foo'], 'a', 'bar'))
    self.assertEquals("'foo foo'",
        cmd_helper.ShrinkToSnippet(['foo foo'], 'a', 'bar'))
    self.assertEquals('"$a"\' bar\'',
        cmd_helper.ShrinkToSnippet(['foo bar'], 'a', 'foo'))
    self.assertEquals('\'foo \'"$a"',
        cmd_helper.ShrinkToSnippet(['foo bar'], 'a', 'bar'))
    self.assertEquals('foo"$a"',
        cmd_helper.ShrinkToSnippet(['foobar'], 'a', 'bar'))

  def testShrinkToSnippet_singleArg(self):
    self.assertEquals("foo ''",
        cmd_helper.ShrinkToSnippet(['foo', ''], 'a', 'bar'))
    self.assertEquals("foo foo",
        cmd_helper.ShrinkToSnippet(['foo', 'foo'], 'a', 'bar'))
    self.assertEquals('"$a" "$a"',
        cmd_helper.ShrinkToSnippet(['foo', 'foo'], 'a', 'foo'))
    self.assertEquals('foo "$a""$a"',
        cmd_helper.ShrinkToSnippet(['foo', 'barbar'], 'a', 'bar'))
    self.assertEquals('foo "$a"\' \'"$a"',
        cmd_helper.ShrinkToSnippet(['foo', 'bar bar'], 'a', 'bar'))
    self.assertEquals('foo "$a""$a"\' \'',
        cmd_helper.ShrinkToSnippet(['foo', 'barbar '], 'a', 'bar'))
    self.assertEquals('foo \' \'"$a""$a"\' \'',
        cmd_helper.ShrinkToSnippet(['foo', ' barbar '], 'a', 'bar'))


_DEFAULT = 'DEFAULT'


class _ProcessOutputEvent(object):

  def __init__(self, select_fds=_DEFAULT, read_contents=None, ts=_DEFAULT):
    self.select_fds = select_fds
    self.read_contents = read_contents
    self.ts = ts


class _MockProcess(object):

  def __init__(self, output_sequence=None, return_value=0):

    # Arbitrary.
    fake_stdout_fileno = 25

    self.mock_proc = mock.MagicMock(spec=subprocess.Popen)
    self.mock_proc.stdout = mock.MagicMock()
    self.mock_proc.stdout.fileno = mock.MagicMock(
        return_value=fake_stdout_fileno)
    self.mock_proc.returncode = None

    self._return_value = return_value

    # This links the behavior of os.read, select.select, time.time, and
    # <process>.poll. The output sequence can be thought of as a list of
    # return values for select.select with corresponding return values for
    # the other calls at any time between that select call and the following
    # one. We iterate through the sequence only on calls to select.select.
    #
    # os.read is a special case, though, where we only return a given chunk
    # of data *once* after a given call to select.

    if not output_sequence:
      output_sequence = []

    # Use an leading element to make the iteration logic work.
    initial_seq_element = _ProcessOutputEvent(
        _DEFAULT, '',
        output_sequence[0].ts if output_sequence else _DEFAULT)
    output_sequence.insert(0, initial_seq_element)

    for o in output_sequence:
      if o.select_fds == _DEFAULT:
        if o.read_contents is None:
          o.select_fds = []
        else:
          o.select_fds = [fake_stdout_fileno]
      if o.ts == _DEFAULT:
        o.ts = time.time()
    self._output_sequence = output_sequence

    self._output_seq_index = 0
    self._read_flags = [False] * len(output_sequence)

    def read_side_effect(*_args, **_kwargs):
      if self._read_flags[self._output_seq_index]:
        return None
      self._read_flags[self._output_seq_index] = True
      return self._output_sequence[self._output_seq_index].read_contents

    def select_side_effect(*_args, **_kwargs):
      if self._output_seq_index is None:
        self._output_seq_index = 0
      else:
        self._output_seq_index += 1
      return (self._output_sequence[self._output_seq_index].select_fds,
              None, None)

    def time_side_effect(*_args, **_kwargs):
      return self._output_sequence[self._output_seq_index].ts

    def poll_side_effect(*_args, **_kwargs):
      if self._output_seq_index >= len(self._output_sequence) - 1:
        self.mock_proc.returncode = self._return_value
      return self.mock_proc.returncode

    mock_read = mock.MagicMock(side_effect=read_side_effect)
    mock_select = mock.MagicMock(side_effect=select_side_effect)
    mock_time = mock.MagicMock(side_effect=time_side_effect)
    self.mock_proc.poll = mock.MagicMock(side_effect=poll_side_effect)

    # Set up but *do not start* the mocks.
    self._mocks = [
      mock.patch('fcntl.fcntl'),
      mock.patch('os.read', new=mock_read),
      mock.patch('select.select', new=mock_select),
      mock.patch('time.time', new=mock_time),
    ]

  def __enter__(self):
    for m in self._mocks:
      m.__enter__()
    return self.mock_proc

  def __exit__(self, exc_type, exc_val, exc_tb):
    for m in reversed(self._mocks):
      m.__exit__(exc_type, exc_val, exc_tb)


class CmdHelperIterCmdOutputLinesTest(unittest.TestCase):
  """Test IterCmdOutputLines with some calls to the unix 'seq' command."""

  # This calls _IterCmdOutputLines rather than IterCmdOutputLines s.t. it
  # can mock the process.
  # pylint: disable=protected-access

  _SIMPLE_OUTPUT_SEQUENCE = [
    _ProcessOutputEvent(read_contents='1\n2\n'),
  ]

  def testIterCmdOutputLines_success(self):
    with _MockProcess(
        output_sequence=self._SIMPLE_OUTPUT_SEQUENCE) as mock_proc:
      for num, line in enumerate(
          cmd_helper._IterCmdOutputLines(mock_proc, 'mock_proc'), 1):
        self.assertEquals(num, int(line))

  def testIterCmdOutputLines_exitStatusFail(self):
    with self.assertRaises(subprocess.CalledProcessError):
      with _MockProcess(output_sequence=self._SIMPLE_OUTPUT_SEQUENCE,
                        return_value=1) as mock_proc:
        for num, line in enumerate(
            cmd_helper._IterCmdOutputLines(mock_proc, 'mock_proc'), 1):
          self.assertEquals(num, int(line))
        # after reading all the output we get an exit status of 1

  def testIterCmdOutputLines_exitStatusIgnored(self):
    with _MockProcess(output_sequence=self._SIMPLE_OUTPUT_SEQUENCE,
                      return_value=1) as mock_proc:
      for num, line in enumerate(
          cmd_helper._IterCmdOutputLines(
              mock_proc, 'mock_proc', check_status=False),
          1):
        self.assertEquals(num, int(line))

  def testIterCmdOutputLines_exitStatusSkipped(self):
    with _MockProcess(output_sequence=self._SIMPLE_OUTPUT_SEQUENCE,
                      return_value=1) as mock_proc:
      for num, line in enumerate(
          cmd_helper._IterCmdOutputLines(mock_proc, 'mock_proc'), 1):
        self.assertEquals(num, int(line))
        # no exception will be raised because we don't attempt to read past
        # the end of the output and, thus, the status never gets checked
        if num == 2:
          break

  def testIterCmdOutputLines_delay(self):
    output_sequence = [
      _ProcessOutputEvent(read_contents='1\n2\n', ts=1),
      _ProcessOutputEvent(read_contents=None, ts=2),
      _ProcessOutputEvent(read_contents='Awake', ts=10),
    ]
    with _MockProcess(output_sequence=output_sequence) as mock_proc:
      for num, line in enumerate(
          cmd_helper._IterCmdOutputLines(mock_proc, 'mock_proc',
                                         iter_timeout=5), 1):
        if num <= 2:
          self.assertEquals(num, int(line))
        elif num == 3:
          self.assertEquals(None, line)
        elif num == 4:
          self.assertEquals('Awake', line)
        else:
          self.fail()


if __name__ == '__main__':
  unittest.main()
