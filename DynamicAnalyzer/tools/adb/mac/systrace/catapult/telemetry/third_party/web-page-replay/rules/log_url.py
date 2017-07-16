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

import logging
import re

from rules import rule


class LogUrl(rule.Rule):
  """Logs the request URL."""

  def __init__(self, url, stop=False):
    r"""Initializes with a url pattern.

    Args:
      url: a string regex, e.g. r'example\.com/id=(\d{6})'.
      stop:  boolean ApplyRule should_stop value, defaults to True.
    """
    self._url_re = re.compile(url)
    self._stop = stop

  def IsType(self, rule_type_name):
    """Returns True if the name matches this rule."""
    return rule_type_name == 'log_url'

  def ApplyRule(self, return_value, request, response):
    """Returns True if logged.

    Args:
      return_value: the prior log_url rule's return_value (if any).
      request: the httparchive ArchivedHttpRequest.
      response: the httparchive ArchivedHttpResponse.
    Returns:
      A (should_stop, return_value) tuple, e.g. (False, True).
    """
    del response  # unused.
    url = '%s%s' % (request.host, request.full_path)
    if not self._url_re.match(url):
      return False, return_value

    logging.debug('url: %s', url)
    return self._stop, True

  def __str__(self):
    return _ToString(self, ('url', self._url_re.pattern),
                     None if self._stop else ('stop', False))

  def __repr__(self):
    return str(self)


def _ToString(obj, *items):
  pkg = (obj.__module__[:obj.__module__.rfind('.') + 1]
         if '.' in obj.__module__ else '')
  clname = obj.__class__.__name__
  args = [('%s=r\'%s\'' % item if isinstance(item[1], basestring)
           else '%s=%s' % item) for item in items if item]
  return '%s%s(%s)' % (pkg, clname, ', '.join(args))
