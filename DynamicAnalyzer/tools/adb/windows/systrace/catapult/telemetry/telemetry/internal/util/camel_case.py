# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re


def ToUnderscore(obj):
  """Converts a string, list, or dict from camelCase to lower_with_underscores.

  Descends recursively into lists and dicts, converting all dict keys.
  Returns a newly allocated object of the same structure as the input.
  """
  if isinstance(obj, basestring):
    return re.sub('(?!^)([A-Z]+)', r'_\1', obj).lower()

  elif isinstance(obj, list):
    return [ToUnderscore(item) for item in obj]

  elif isinstance(obj, dict):
    output = {}
    for k, v in obj.iteritems():
      if isinstance(v, list) or isinstance(v, dict):
        output[ToUnderscore(k)] = ToUnderscore(v)
      else:
        output[ToUnderscore(k)] = v
    return output

  else:
    return obj
