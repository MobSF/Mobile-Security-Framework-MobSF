# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import difflib


def GetMostLikelyMatchedObject(objects, target_name,
                               name_func=lambda x: x,
                               matched_score_threshold=0.4):
  """Matches objects whose names are most likely matched with target.

  Args:
    objects: list of objects to match.
    target_name: name to match.
    name_func: function to get object name to match. Default bypass.
    matched_score_threshold: threshold of likelihood to match.

  Returns:
    A list of objects whose names are likely target_name.
  """
  def MatchScore(obj):
    return difflib.SequenceMatcher(
        isjunk=None, a=name_func(obj), b=target_name).ratio()
  object_score = [(o, MatchScore(o)) for o in objects]
  result = [x for x in object_score if x[1] > matched_score_threshold]
  return [x[0] for x in sorted(result, key=lambda r: r[1], reverse=True)]
