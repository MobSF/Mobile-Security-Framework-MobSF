#!/usr/bin/env python
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


class Rule(object):
  """An optional base class for rule implementations.

  The rule_parser looks for the 'IsType' and 'ApplyRule' methods by name, so
  rules are not strictly required to extend this class.
  """

  def IsType(self, rule_type_name):
    """Returns True if the name matches this rule."""
    raise NotImplementedError

  def ApplyRule(self, return_value, request, response):
    """Invokes this rule with the given args.

    Args:
      return_value: the prior rule's return_value (if any).
      request: the httparchive ArchivedHttpRequest.
      response: the httparchive ArchivedHttpResponse, which may be None.
    Returns:
      A (should_stop, return_value) tuple.  Typically the request and response
        are treated as immutable, so it's the caller's job to apply the
        return_value (e.g., set response fields).
    """
    raise NotImplementedError
