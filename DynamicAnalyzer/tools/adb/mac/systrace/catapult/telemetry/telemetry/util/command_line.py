# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse

from telemetry.internal.util import command_line


class ArgParseCommand(command_line.Command):
  usage = ''

  @classmethod
  def CreateParser(cls):
    return argparse.ArgumentParser('%%prog %s %s' % (cls.Name(), cls.usage),
                                   description=cls.Description())

  @classmethod
  def AddCommandLineArgs(cls, parser, environment):
    # pylint: disable=arguments-differ
    pass

  @classmethod
  def ProcessCommandLineArgs(cls, parser, options, extra_args, environment):
    # pylint: disable=arguments-differ
    pass

  def Run(self, options, extra_args=None):
    # pylint: disable=arguments-differ
    raise NotImplementedError()

  @classmethod
  def main(cls, args=None):
    """Main method to run this command as a standalone script."""
    parser = cls.CreateParser()
    cls.AddCommandLineArgs(parser, None)
    options, extra_args = parser.parse_known_args(args=args)
    cls.ProcessCommandLineArgs(parser, options, extra_args, None)
    return min(cls().Run(options, extra_args), 255)
