# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import optparse

from telemetry.internal.util import camel_case


class ArgumentHandlerMixIn(object):
  """A structured way to handle command-line arguments.

  In AddCommandLineArgs, add command-line arguments.
  In ProcessCommandLineArgs, validate them and store them in a private class
  variable. This way, each class encapsulates its own arguments, without needing
  to pass an arguments object around everywhere.
  """

  @classmethod
  def AddCommandLineArgs(cls, parser):
    """Override to accept custom command-line arguments."""

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    """Override to process command-line arguments.

    We pass in parser so we can call parser.error()."""


class Command(ArgumentHandlerMixIn):
  """An abstraction for things that run from the command-line."""

  @classmethod
  def Name(cls):
    return camel_case.ToUnderscore(cls.__name__)

  @classmethod
  def Description(cls):
    if cls.__doc__:
      return cls.__doc__.splitlines()[0]
    else:
      return ''

  def Run(self, args):
    raise NotImplementedError()

  @classmethod
  def main(cls, args=None):
    """Main method to run this command as a standalone script."""
    parser = argparse.ArgumentParser()
    cls.AddCommandLineArgs(parser)
    args = parser.parse_args(args=args)
    cls.ProcessCommandLineArgs(parser, args)
    return min(cls().Run(args), 255)


# TODO: Convert everything to argparse.
class OptparseCommand(Command):
  usage = ''

  @classmethod
  def CreateParser(cls):
    return optparse.OptionParser('%%prog %s %s' % (cls.Name(), cls.usage),
                                 description=cls.Description())

  @classmethod
  def AddCommandLineArgs(cls, parser, environment):
    # pylint: disable=arguments-differ
    pass

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args, environment):
    # pylint: disable=arguments-differ
    pass

  def Run(self, args):
    raise NotImplementedError()

  @classmethod
  def main(cls, args=None):
    """Main method to run this command as a standalone script."""
    parser = cls.CreateParser()
    cls.AddCommandLineArgs(parser, None)
    options, args = parser.parse_args(args=args)
    options.positional_args = args
    cls.ProcessCommandLineArgs(parser, options, None)
    return min(cls().Run(options), 255)


class SubcommandCommand(Command):
  """Combines Commands into one big command with sub-commands.

  E.g. "svn checkout", "svn update", and "svn commit" are separate sub-commands.

  Example usage:
    class MyCommand(command_line.SubcommandCommand):
      commands = (Help, List, Run)

    if __name__ == '__main__':
      sys.exit(MyCommand.main())
  """

  commands = ()

  @classmethod
  def AddCommandLineArgs(cls, parser):
    subparsers = parser.add_subparsers()

    for command in cls.commands:
      subparser = subparsers.add_parser(
          command.Name(), help=command.Description())
      subparser.set_defaults(command=command)
      command.AddCommandLineArgs(subparser)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    args.command.ProcessCommandLineArgs(parser, args)

  def Run(self, args):
    return args.command().Run(args)
