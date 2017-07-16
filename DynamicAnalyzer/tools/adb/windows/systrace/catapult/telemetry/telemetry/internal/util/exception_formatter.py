# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Print prettier and more detailed exceptions."""

import logging
import math
import os
import sys
import traceback

from telemetry.core import exceptions


def PrintFormattedException(exception_class=None, exception=None, tb=None,
                            msg=None):
  logging.info('Try printing formatted exception: %s %s %s' %
               (exception_class, exception, tb))
  assert bool(exception_class) == bool(exception) == bool(tb), (
      'Must specify all or none of exception_class, exception, and tb')

  if not exception_class:
    exception_class, exception, tb = sys.exc_info()

  if exception_class == exceptions.IntentionalException:
    return

  def _GetFinalFrame(tb_level):
    while tb_level.tb_next:
      tb_level = tb_level.tb_next
    return tb_level.tb_frame

  processed_tb = traceback.extract_tb(tb)
  frame = _GetFinalFrame(tb)
  exception_list = traceback.format_exception_only(exception_class, exception)
  exception_string = '\n'.join(l.strip() for l in exception_list)

  if msg:
    print >> sys.stderr
    print >> sys.stderr, msg

  _PrintFormattedTrace(processed_tb, frame, exception_string)


def PrintFormattedFrame(frame, exception_string=None):
  _PrintFormattedTrace(traceback.extract_stack(frame), frame, exception_string)


def _PrintFormattedTrace(processed_tb, frame, exception_string=None):
  """Prints an Exception in a more useful format than the default.

  TODO(tonyg): Consider further enhancements. For instance:
    - Report stacks to maintainers like depot_tools does.
    - Add a debug flag to automatically start pdb upon exception.
  """
  print >> sys.stderr

  # Format the traceback.
  print >> sys.stderr, 'Traceback (most recent call last):'
  for filename, line, function, text in processed_tb:
    filename = os.path.abspath(filename)
    print >> sys.stderr, '  %s at %s:%d' % (function, filename, line)
    print >> sys.stderr, '    %s' % text

  # Format the exception.
  if exception_string:
    print >> sys.stderr, exception_string

  # Format the locals.
  local_variables = [(variable, value) for variable, value in
                     frame.f_locals.iteritems() if variable != 'self']
  print >> sys.stderr
  print >> sys.stderr, 'Locals:'
  if local_variables:
    longest_variable = max(len(v) for v, _ in local_variables)
    for variable, value in sorted(local_variables):
      value = repr(value)
      possibly_truncated_value = _AbbreviateMiddleOfString(value, ' ... ', 1024)
      truncation_indication = ''
      if len(possibly_truncated_value) != len(value):
        truncation_indication = ' (truncated)'
      print >> sys.stderr, '  %s: %s%s' % (variable.ljust(longest_variable + 1),
                                           possibly_truncated_value,
                                           truncation_indication)
  else:
    print >> sys.stderr, '  No locals!'

  print >> sys.stderr
  sys.stderr.flush()


def _AbbreviateMiddleOfString(target, middle, max_length):
  if max_length < 0:
    raise ValueError('Must provide positive max_length')
  if len(middle) > max_length:
    raise ValueError('middle must not be greater than max_length')

  if len(target) <= max_length:
    return target
  half_length = (max_length - len(middle)) / 2.
  return (target[:int(math.floor(half_length))] + middle +
          target[-int(math.ceil(half_length)):])
