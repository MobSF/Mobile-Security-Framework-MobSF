#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
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

"""Mock instance of ArchivedHttpRequest used for testing."""


class ArchivedHttpRequest(object):
  """Mock instance of ArchivedHttpRequest in HttpArchive."""

  def __init__(self, command, host, path, request_body, headers):
    """Initialize an ArchivedHttpRequest.

    Args:
      command: a string (e.g. 'GET' or 'POST').
      host: a host name (e.g. 'www.google.com').
      path: a request path (e.g. '/search?q=dogs').
      request_body: a request body string for a POST or None.
      headers: [(header1, value1), ...] list of tuples
    """
    self.command = command
    self.host = host
    self.path = path
    self.request_body = request_body
    self.headers = headers
    self.trimmed_headers = headers

  def __str__(self):
    return '%s %s%s %s' % (self.command, self.host, self.path,
                           self.trimmed_headers)

  def __repr__(self):
    return repr((self.command, self.host, self.path, self.request_body,
                 self.trimmed_headers))

  def __hash__(self):
    """Return a integer hash to use for hashed collections including dict."""
    return hash(repr(self))

  def __eq__(self, other):
    """Define the __eq__ method to match the hash behavior."""
    return repr(self) == repr(other)

  def matches(self, command=None, host=None, path=None):
    """Returns true iff the request matches all parameters."""
    return ((command is None or command == self.command) and
            (host is None or host == self.host) and
            (path is None or path == self.path))
