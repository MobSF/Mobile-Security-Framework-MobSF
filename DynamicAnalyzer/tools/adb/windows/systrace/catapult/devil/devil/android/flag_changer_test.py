#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import posixpath
import unittest

from devil.android import flag_changer


_CMDLINE_FILE = 'chrome-command-line'


class _FakeDevice(object):
  def __init__(self):
    self.build_type = 'user'
    self.has_root = True
    self.file_system = {}

  def HasRoot(self):
    return self.has_root

  def PathExists(self, filepath):
    return filepath in self.file_system

  def RemovePath(self, path, **_kwargs):
    self.file_system.pop(path)

  def WriteFile(self, path, contents, **_kwargs):
    self.file_system[path] = contents

  def ReadFile(self, path, **_kwargs):
    return self.file_system[path]


class FlagChangerTest(unittest.TestCase):
  def setUp(self):
    self.device = _FakeDevice()
    # pylint: disable=protected-access
    self.cmdline_path = posixpath.join(flag_changer._CMDLINE_DIR, _CMDLINE_FILE)
    self.cmdline_path_legacy = posixpath.join(
        flag_changer._CMDLINE_DIR_LEGACY, _CMDLINE_FILE)

  def testFlagChanger_removeLegacyCmdLine(self):
    self.device.WriteFile(self.cmdline_path_legacy, 'chrome --old --stuff')
    self.assertTrue(self.device.PathExists(self.cmdline_path_legacy))

    changer = flag_changer.FlagChanger(self.device, 'chrome-command-line')
    self.assertEquals(
        changer._cmdline_path,  # pylint: disable=protected-access
        self.cmdline_path)
    self.assertFalse(self.device.PathExists(self.cmdline_path_legacy))

  def testFlagChanger_mustBeFileName(self):
    with self.assertRaises(ValueError):
      flag_changer.FlagChanger(self.device, '/data/local/chrome-command-line')


class ParseSerializeFlagsTest(unittest.TestCase):
  def _testQuoteFlag(self, flag, expected_quoted_flag):
    # Start with an unquoted flag, check that it's quoted as expected.
    # pylint: disable=protected-access
    quoted_flag = flag_changer._QuoteFlag(flag)
    self.assertEqual(quoted_flag, expected_quoted_flag)
    # Check that it survives a round-trip.
    parsed_flags = flag_changer._ParseFlags('_ %s' % quoted_flag)
    self.assertEqual(len(parsed_flags), 1)
    self.assertEqual(flag, parsed_flags[0])

  def testQuoteFlag_simple(self):
    self._testQuoteFlag('--simple-flag', '--simple-flag')

  def testQuoteFlag_withSimpleValue(self):
    self._testQuoteFlag('--key=value', '--key=value')

  def testQuoteFlag_withQuotedValue1(self):
    self._testQuoteFlag('--key=valueA valueB', '--key="valueA valueB"')

  def testQuoteFlag_withQuotedValue2(self):
    self._testQuoteFlag(
        '--key=this "should" work', r'--key="this \"should\" work"')

  def testQuoteFlag_withQuotedValue3(self):
    self._testQuoteFlag(
        "--key=this is 'fine' too", '''--key="this is 'fine' too"''')

  def testQuoteFlag_withQuotedValue4(self):
    self._testQuoteFlag(
        "--key='I really want to keep these quotes'",
        '''--key="'I really want to keep these quotes'"''')

  def testQuoteFlag_withQuotedValue5(self):
    self._testQuoteFlag(
        "--this is a strange=flag", '"--this is a strange=flag"')

  def testQuoteFlag_withEmptyValue(self):
    self._testQuoteFlag('--some-flag=', '--some-flag=')

  def _testParseCmdLine(self, command_line, expected_flags):
    # Start with a command line, check that flags are parsed as expected.
    # pylint: disable=protected-access
    flags = flag_changer._ParseFlags(command_line)
    self.assertItemsEqual(flags, expected_flags)

    # Check that flags survive a round-trip.
    # Note: Although new_command_line and command_line may not match, they
    # should describe the same set of flags.
    new_command_line = flag_changer._SerializeFlags(flags)
    new_flags = flag_changer._ParseFlags(new_command_line)
    self.assertItemsEqual(new_flags, expected_flags)

  def testParseCmdLine_simple(self):
    self._testParseCmdLine(
        'chrome --foo --bar="a b" --baz=true --fine="ok"',
        ['--foo', '--bar=a b', '--baz=true', '--fine=ok'])

  def testParseCmdLine_withFancyQuotes(self):
    self._testParseCmdLine(
        r'''_ --foo="this 'is' ok"
              --bar='this \'is\' too'
              --baz="this \'is\' tricky"
        ''',
        ["--foo=this 'is' ok",
         "--bar=this 'is' too",
         r"--baz=this \'is\' tricky"])

  def testParseCmdLine_withUnterminatedQuote(self):
    self._testParseCmdLine(
        '_ --foo --bar="I forgot something',
        ['--foo', '--bar=I forgot something'])


if __name__ == '__main__':
  unittest.main(verbosity=2)
