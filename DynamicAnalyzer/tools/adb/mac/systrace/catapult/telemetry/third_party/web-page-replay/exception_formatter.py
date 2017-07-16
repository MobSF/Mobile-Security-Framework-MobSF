# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import math
import os
import sys
import traceback


def PrintFormattedException(msg=None):
  exception_class, exception, tb = sys.exc_info()

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
  """
  print >> sys.stderr

  # Format the traceback.
  base_dir = os.path.dirname(__file__)
  print >> sys.stderr, 'Traceback (most recent call last):'
  for filename, line, function, text in processed_tb:
    filename = os.path.abspath(filename)
    if filename.startswith(base_dir):
      filename = filename[len(base_dir)+1:]
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
