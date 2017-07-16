# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

MERGE_FAILURE_REASON = (
    'Merging values containing a None value results in a None value.')

class NoneValueMissingReason(Exception):
  pass

class ValueMustHaveNoneValue(Exception):
  pass

def ValidateNoneValueReason(value, none_value_reason):
  """Ensures that the none_value_reason is appropriate for the given value.

  There is a logical equality between having a value of None and having a
  reason for being None. That is to say, value is None if and only if
  none_value_reason is a string.
  """
  if value is None and not isinstance(none_value_reason, basestring):
    raise NoneValueMissingReason()
  if value is not None and none_value_reason is not None:
    raise ValueMustHaveNoneValue()
