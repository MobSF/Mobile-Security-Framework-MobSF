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

"""View and edit HTTP Archives.

To list all URLs in an archive:
  $ ./httparchive.py ls archive.wpr

To view the content of all URLs from example.com:
  $ ./httparchive.py cat --host example.com archive.wpr

To view the content of a particular URL:
  $ ./httparchive.py cat --host www.example.com --full_path /foo archive.wpr

To view the content of all URLs:
  $ ./httparchive.py cat archive.wpr

To edit a particular URL:
  $ ./httparchive.py edit --host www.example.com --full_path /foo archive.wpr

To print statistics of an archive:
  $ ./httparchive.py stats archive.wpr

To print statistics of a set of URLs:
  $ ./httparchive.py stats --host www.example.com archive.wpr

To merge multiple archives
  $ ./httparchive.py merge --merged_file new.wpr archive1.wpr archive2.wpr ...
"""

import calendar
import certutils
import datetime
import cPickle
import difflib
import email.utils
import httplib
import httpzlib
import json
import logging
import optparse
import os
import StringIO
import subprocess
import sys
import tempfile
import time
import urlparse
from collections import defaultdict



def LogRunTime(fn):
  """Annotation which logs the run time of the function."""
  def wrapped(self, *args, **kwargs):
    start_time = time.time()
    try:
      return fn(self, *args, **kwargs)
    finally:
      run_time = (time.time() - start_time) * 1000.0
      logging.debug('%s: %dms', fn.__name__, run_time)
  return wrapped


class HttpArchiveException(Exception):
  """Base class for all exceptions in httparchive."""
  pass


class HttpArchive(dict):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values.

  Attributes:
    responses_by_host: dict of {hostname, {request: response}}. This must remain
        in sync with the underlying dict of self. It is used as an optimization
        so that get_requests() doesn't have to linearly search all requests in
        the archive to find potential matches.
  """

  def __init__(self):  # pylint: disable=super-init-not-called
    self.responses_by_host = defaultdict(dict)

  def __setstate__(self, state):
    """Influence how to unpickle.

    Args:
      state: a dictionary for __dict__
    """
    self.__dict__.update(state)
    self.responses_by_host = defaultdict(dict)
    for request in self:
      self.responses_by_host[request.host][request] = self[request]

  def __getstate__(self):
    """Influence how to pickle.

    Returns:
      a dict to use for pickling
    """
    state = self.__dict__.copy()
    del state['responses_by_host']
    return state

  def __setitem__(self, key, value):
    super(HttpArchive, self).__setitem__(key, value)
    if hasattr(self, 'responses_by_host'):
      self.responses_by_host[key.host][key] = value

  def __delitem__(self, key):
    super(HttpArchive, self).__delitem__(key)
    del self.responses_by_host[key.host][key]

  def get(self, request, default=None):
    """Return the archived response for a given request.

    Does extra checking for handling some HTTP request headers.

    Args:
      request: instance of ArchivedHttpRequest
      default: default value to return if request is not found

    Returns:
      Instance of ArchivedHttpResponse or default if no matching
      response is found
    """
    if request in self:
      return self[request]
    return self.get_conditional_response(request, default)

  def get_conditional_response(self, request, default):
    """Get the response based on the conditional HTTP request headers.

    Args:
      request: an ArchivedHttpRequest representing the original request.
      default: default ArchivedHttpResponse
          original request with matched headers removed.

    Returns:
      an ArchivedHttpResponse with a status of 200, 302 (not modified), or
          412 (precondition failed)
    """
    response = default
    if request.is_conditional():
      stripped_request = request.create_request_without_conditions()
      if stripped_request in self:
        response = self[stripped_request]
        if response.status == 200:
          status = self.get_conditional_status(request, response)
          if status != 200:
            response = create_response(status)
    return response

  def get_conditional_status(self, request, response):
    status = 200
    last_modified = email.utils.parsedate(
        response.update_date(response.get_header('last-modified')))
    response_etag = response.get_header('etag')
    is_get_or_head = request.command.upper() in ('GET', 'HEAD')

    match_value = request.headers.get('if-match', None)
    if match_value:
      if self.is_etag_match(match_value, response_etag):
        status = 200
      else:
        status = 412  # precondition failed
    none_match_value = request.headers.get('if-none-match', None)
    if none_match_value:
      if self.is_etag_match(none_match_value, response_etag):
        status = 304
      elif is_get_or_head:
        status = 200
      else:
        status = 412
    if is_get_or_head and last_modified:
      for header in ('if-modified-since', 'if-unmodified-since'):
        date = email.utils.parsedate(request.headers.get(header, None))
        if date:
          if ((header == 'if-modified-since' and last_modified > date) or
              (header == 'if-unmodified-since' and last_modified < date)):
            if status != 412:
              status = 200
          else:
            status = 304  # not modified
    return status

  @staticmethod
  def is_etag_match(request_etag, response_etag):
    """Determines whether the entity tags of the request/response matches.

    Args:
      request_etag: the value string of the "if-(none)-match:"
                    portion of the request header
      response_etag: the etag value of the response

    Returns:
      True on match, False otherwise
    """
    response_etag = response_etag.strip('" ')
    for etag in request_etag.split(','):
      etag = etag.strip('" ')
      if etag in ('*', response_etag):
        return True
    return False

  def get_requests(self, command=None, host=None, full_path=None, is_ssl=None,
                   use_query=True):
    """Return a list of requests that match the given args."""
    if host:
      return [r for r in self.responses_by_host[host]
              if r.matches(command, None, full_path, is_ssl,
                           use_query=use_query)]
    else:
      return [r for r in self
              if r.matches(command, host, full_path, is_ssl,
                           use_query=use_query)]

  def ls(self, command=None, host=None, full_path=None):
    """List all URLs that match given params."""
    return ''.join(sorted(
        '%s\n' % r for r in self.get_requests(command, host, full_path)))

  def cat(self, command=None, host=None, full_path=None):
    """Print the contents of all URLs that match given params."""
    out = StringIO.StringIO()
    for request in self.get_requests(command, host, full_path):
      print >>out, str(request)
      print >>out, 'Untrimmed request headers:'
      for k in request.headers:
        print >>out, '    %s: %s' % (k, request.headers[k])
      if request.request_body:
        print >>out, request.request_body
      print >>out, '---- Response Info', '-' * 51
      response = self[request]
      chunk_lengths = [len(x) for x in response.response_data]
      print >>out, ('Status: %s\n'
                    'Reason: %s\n'
                    'Headers delay: %s\n'
                    'Untrimmed response headers:') % (
          response.status, response.reason, response.delays['headers'])
      for k, v in response.original_headers:
        print >>out, '    %s: %s' % (k, v)
      print >>out, ('Chunk count: %s\n'
                    'Chunk lengths: %s\n'
                    'Chunk delays: %s') % (
          len(chunk_lengths), chunk_lengths, response.delays['data'])
      body = response.get_data_as_text()
      print >>out, '---- Response Data', '-' * 51
      if body:
        print >>out, body
      else:
        print >>out, '[binary data]'
      print >>out, '=' * 70
    return out.getvalue()

  def stats(self, command=None, host=None, full_path=None):
    """Print stats about the archive for all URLs that match given params."""
    matching_requests = self.get_requests(command, host, full_path)
    if not matching_requests:
      print 'Failed to find any requests matching given command, host, path.'
      return

    out = StringIO.StringIO()
    stats = {
        'Total': len(matching_requests),
        'Domains': defaultdict(int),
        'HTTP_response_code': defaultdict(int),
        'content_type': defaultdict(int),
        'Documents': defaultdict(int),
        }

    for request in matching_requests:
      stats['Domains'][request.host] += 1
      stats['HTTP_response_code'][self[request].status] += 1

      content_type = self[request].get_header('content-type')
      # Remove content type options for readability and higher level groupings.
      str_content_type = str(content_type.split(';')[0]
                            if content_type else None)
      stats['content_type'][str_content_type] += 1

      #  Documents are the main URL requested and not a referenced resource.
      if str_content_type == 'text/html' and not 'referer' in request.headers:
        stats['Documents'][request.host] += 1

    print >>out, json.dumps(stats, indent=4)
    return out.getvalue()

  def merge(self, merged_archive=None, other_archives=None):
    """Merge multiple archives into merged_archive by 'chaining' resources,
    only resources that are not part of the accumlated archive are added"""
    if not other_archives:
      print 'No archives passed to merge'
      return

    # Note we already loaded 'replay_file'.
    print 'Loaded %d responses' % len(self)

    for archive in other_archives:
      if not os.path.exists(archive):
        print 'Error: Replay file "%s" does not exist' % archive
        return

      http_archive_other = HttpArchive.Load(archive)
      print 'Loaded %d responses from %s' % (len(http_archive_other), archive)
      for r in http_archive_other:
        # Only resources that are not already part of the current archive
        # get added.
        if r not in self:
          print '\t %s ' % r
          self[r] = http_archive_other[r]
    self.Persist('%s' % merged_archive)

  def edit(self, command=None, host=None, full_path=None):
    """Edits the single request which matches given params."""
    editor = os.getenv('EDITOR')
    if not editor:
      print 'You must set the EDITOR environmental variable.'
      return

    matching_requests = self.get_requests(command, host, full_path)
    if not matching_requests:
      print ('Failed to find any requests matching given command, host, '
             'full_path.')
      return

    if len(matching_requests) > 1:
      print 'Found multiple matching requests. Please refine.'
      print self.ls(command, host, full_path)

    response = self[matching_requests[0]]
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file.write(response.get_response_as_text())
    tmp_file.close()
    subprocess.check_call([editor, tmp_file.name])
    response.set_response_from_text(''.join(open(tmp_file.name).readlines()))
    os.remove(tmp_file.name)

  def find_closest_request(self, request, use_path=False):
    """Find the closest matching request in the archive to the given request.

    Args:
      request: an ArchivedHttpRequest
      use_path: If True, closest matching request's path component must match.
        (Note: this refers to the 'path' component within the URL, not the
         'full path' which includes the query string component.)

        If use_path=True, candidate will NOT match in example below
        e.g. request   = GET www.test.com/a?p=1
             candidate = GET www.test.com/b?p=1

        Even if use_path=False, urls with same paths are always favored.
        For example, candidate1 is considered a better match than candidate2.
          request    = GET www.test.com/a?p=1&q=2&r=3
          candidate1 = GET www.test.com/a?s=4
          candidate2 = GET www.test.com/b?p=1&q=2&r=3

    Returns:
      If a close match is found, return the instance of ArchivedHttpRequest.
      Otherwise, return None.
    """
    # Start with strictest constraints. This trims search space considerably.
    requests = self.get_requests(request.command, request.host,
                                 request.full_path, is_ssl=request.is_ssl,
                                 use_query=True)
    # Relax constraint: use_query if there is no match.
    if not requests:
      requests = self.get_requests(request.command, request.host,
                                   request.full_path, is_ssl=request.is_ssl,
                                   use_query=False)
    # Relax constraint: full_path if there is no match and use_path=False.
    if not requests and not use_path:
      requests = self.get_requests(request.command, request.host,
                                   None, is_ssl=request.is_ssl,
                                   use_query=False)

    if not requests:
      return None

    if len(requests) == 1:
      return requests[0]

    matcher = difflib.SequenceMatcher(b=request.cmp_seq)

    # quick_ratio() is cheap to compute, but ratio() is expensive. So we call
    # quick_ratio() on all requests, sort them descending, and then loop through
    # until we find a candidate whose ratio() is >= the next quick_ratio().
    # This works because quick_ratio() is guaranteed to be an upper bound on
    # ratio().
    candidates = []
    for candidate in requests:
      matcher.set_seq1(candidate.cmp_seq)
      candidates.append((matcher.quick_ratio(), candidate))

    candidates.sort(reverse=True, key=lambda c: c[0])

    best_match = (0, None)
    for i in xrange(len(candidates)):
      matcher.set_seq1(candidates[i][1].cmp_seq)
      best_match = max(best_match, (matcher.ratio(), candidates[i][1]))
      if i + 1 < len(candidates) and best_match[0] >= candidates[i+1][0]:
        break
    return best_match[1]

  def diff(self, request):
    """Diff the given request to the closest matching request in the archive.

    Args:
      request: an ArchivedHttpRequest
    Returns:
      If a close match is found, return a textual diff between the requests.
      Otherwise, return None.
    """
    request_lines = request.formatted_request.split('\n')
    closest_request = self.find_closest_request(request)
    if closest_request:
      closest_request_lines = closest_request.formatted_request.split('\n')
      return '\n'.join(difflib.ndiff(closest_request_lines, request_lines))
    return None

  def get_server_cert(self, host):
    """Gets certificate from the server and stores it in archive"""
    request = ArchivedHttpRequest('SERVER_CERT', host, '', None, {})
    if request not in self:
      self[request] = create_response(200, body=certutils.get_host_cert(host))
    return self[request].response_data[0]

  def get_certificate(self, host):
    request = ArchivedHttpRequest('DUMMY_CERT', host, '', None, {})
    if request not in self:
      self[request] = create_response(200, body=self._generate_cert(host))
    return self[request].response_data[0]

  @classmethod
  def AssertWritable(cls, filename):
    """Raises an IOError if filename is not writable."""
    persist_dir = os.path.dirname(os.path.abspath(filename))
    if not os.path.exists(persist_dir):
      raise IOError('Directory does not exist: %s' % persist_dir)
    if os.path.exists(filename):
      if not os.access(filename, os.W_OK):
        raise IOError('Need write permission on file: %s' % filename)
    elif not os.access(persist_dir, os.W_OK):
      raise IOError('Need write permission on directory: %s' % persist_dir)

  @classmethod
  def Load(cls, filename):
    """Load an instance from filename."""
    return cPickle.load(open(filename, 'rb'))

  def Persist(self, filename):
    """Persist all state to filename."""
    try:
      original_checkinterval = sys.getcheckinterval()
      sys.setcheckinterval(2**31-1)  # Lock out other threads so nothing can
                                     # modify |self| during pickling.
      pickled_self = cPickle.dumps(self, cPickle.HIGHEST_PROTOCOL)
    finally:
      sys.setcheckinterval(original_checkinterval)
    with open(filename, 'wb') as f:
      f.write(pickled_self)


class ArchivedHttpRequest(object):
  """Record all the state that goes into a request.

  ArchivedHttpRequest instances are considered immutable so they can
  serve as keys for HttpArchive instances.
  (The immutability is not enforced.)

  Upon creation, the headers are "trimmed" (i.e. edited or dropped)
  and saved to self.trimmed_headers to allow requests to match in a wider
  variety of playback situations (e.g. using different user agents).

  For unpickling, 'trimmed_headers' is recreated from 'headers'. That
  allows for changes to the trim function and can help with debugging.
  """
  CONDITIONAL_HEADERS = [
      'if-none-match', 'if-match',
      'if-modified-since', 'if-unmodified-since']

  def __init__(self, command, host, full_path, request_body, headers,
               is_ssl=False):
    """Initialize an ArchivedHttpRequest.

    Args:
      command: a string (e.g. 'GET' or 'POST').
      host: a host name (e.g. 'www.google.com').
      full_path: a request path.  Includes everything after the host & port in
          the URL (e.g. '/search?q=dogs').
      request_body: a request body string for a POST or None.
      headers: {key: value, ...} where key and value are strings.
      is_ssl: a boolean which is True iff request is make via SSL.
    """
    self.command = command
    self.host = host
    self.full_path = full_path
    parsed_url = urlparse.urlparse(full_path) if full_path else None
    self.path = parsed_url.path if parsed_url else None
    self.request_body = request_body
    self.headers = headers
    self.is_ssl = is_ssl
    self.trimmed_headers = self._TrimHeaders(headers)
    self.formatted_request = self._GetFormattedRequest()
    self.cmp_seq = self._GetCmpSeq(parsed_url.query if parsed_url else None)

  def __str__(self):
    scheme = 'https' if self.is_ssl else 'http'
    return '%s %s://%s%s %s' % (
        self.command, scheme, self.host, self.full_path, self.trimmed_headers)

  def __repr__(self):
    return repr((self.command, self.host, self.full_path, self.request_body,
                 self.trimmed_headers, self.is_ssl))

  def __hash__(self):
    """Return a integer hash to use for hashed collections including dict."""
    return hash(repr(self))

  def __eq__(self, other):
    """Define the __eq__ method to match the hash behavior."""
    return repr(self) == repr(other)

  def __setstate__(self, state):
    """Influence how to unpickle.

    "headers" are the original request headers.
    "trimmed_headers" are the trimmed headers used for matching requests
    during replay.

    Args:
      state: a dictionary for __dict__
    """
    if 'full_headers' in state:
      # Fix older version of archive.
      state['headers'] = state['full_headers']
      del state['full_headers']
    if 'headers' not in state:
      raise HttpArchiveException(
          'Archived HTTP request is missing "headers". The HTTP archive is'
          ' likely from a previous version and must be re-recorded.')
    if 'path' in state:
      # before, 'path' and 'path_without_query' were used and 'path' was
      # pickled.  Now, 'path' has been renamed to 'full_path' and
      # 'path_without_query' has been renamed to 'path'.  'full_path' is
      # pickled, but 'path' is not.  If we see 'path' here it means we are
      # dealing with an older archive.
      state['full_path'] = state['path']
      del state['path']
    state['trimmed_headers'] = self._TrimHeaders(dict(state['headers']))
    if 'is_ssl' not in state:
      state['is_ssl'] = False
    self.__dict__.update(state)
    parsed_url = urlparse.urlparse(self.full_path)
    self.path = parsed_url.path
    self.formatted_request = self._GetFormattedRequest()
    self.cmp_seq = self._GetCmpSeq(parsed_url.query)

  def __getstate__(self):
    """Influence how to pickle.

    Returns:
      a dict to use for pickling
    """
    state = self.__dict__.copy()
    del state['trimmed_headers']
    del state['path']
    del state['formatted_request']
    del state['cmp_seq']
    return state

  def _GetFormattedRequest(self):
    """Format request to make diffs easier to read.

    Returns:
      A string consisting of the request. Example:
      'GET www.example.com/path\nHeader-Key: header value\n'
    """
    parts = ['%s %s%s\n' % (self.command, self.host, self.full_path)]
    if self.request_body:
      parts.append('%s\n' % self.request_body)
    for k, v in self.trimmed_headers:
      k = '-'.join(x.capitalize() for x in k.split('-'))
      parts.append('%s: %s\n' % (k, v))
    return ''.join(parts)

  def _GetCmpSeq(self, query=None):
    """Compute a sequence out of query and header for difflib to compare.
    For example:
      [('q1', 'a1'), ('q2', 'a2'), ('k1', 'v1'), ('k2', 'v2')]
    will be returned for a request with URL:
      http://example.com/index.html?q1=a2&q2=a2
    and header:
      k1: v1
      k2: v2

    Args:
      query: the query string in the URL.

    Returns:
      A sequence for difflib to compare.
    """
    if not query:
      return self.trimmed_headers
    return sorted(urlparse.parse_qsl(query)) + self.trimmed_headers

  def matches(self, command=None, host=None, full_path=None, is_ssl=None,
              use_query=True):
    """Returns true iff the request matches all parameters.

    Args:
      command: a string (e.g. 'GET' or 'POST').
      host: a host name (e.g. 'www.google.com').
      full_path: a request path with query string (e.g. '/search?q=dogs')
      is_ssl: whether the request is secure.
      use_query:
        If use_query is True, request matching uses both the hierarchical path
        and query string component.
        If use_query is False, request matching only uses the hierarchical path

        e.g. req1 = GET www.test.com/index?aaaa
             req2 = GET www.test.com/index?bbbb

        If use_query is True, req1.matches(req2) evaluates to False
        If use_query is False, req1.matches(req2) evaluates to True

    Returns:
      True iff the request matches all parameters
    """
    if command is not None and command != self.command:
      return False
    if is_ssl is not None and is_ssl != self.is_ssl:
      return False
    if host is not None and host != self.host:
      return False
    if full_path is None:
      return True
    if use_query:
      return full_path == self.full_path
    else:
      return self.path == urlparse.urlparse(full_path).path

  @classmethod
  def _TrimHeaders(cls, headers):
    """Removes headers that are known to cause problems during replay.

    These headers are removed for the following reasons:
    - accept: Causes problems with www.bing.com. During record, CSS is fetched
              with *. During replay, it's text/css.
    - accept-charset, accept-language, referer: vary between clients.
    - cache-control:  sometimes sent from Chrome with 'max-age=0' as value.
    - connection, method, scheme, url, version: Cause problems with spdy.
    - cookie: Extremely sensitive to request/response order.
    - keep-alive: Doesn't affect the content of the request, only some
      transient state of the transport layer.
    - user-agent: Changes with every Chrome version.
    - proxy-connection: Sent for proxy requests.
    - x-chrome-variations, x-client-data: Unique to each Chrome binary. Used by
      Google to collect statistics about Chrome's enabled features.

    Another variant to consider is dropping only the value from the header.
    However, this is particularly bad for the cookie header, because the
    presence of the cookie depends on the responses we've seen when the request
    is made.

    Args:
      headers: {header_key: header_value, ...}

    Returns:
      [(header_key, header_value), ...]  # (with undesirable headers removed)
    """
    # TODO(tonyg): Strip sdch from the request headers because we can't
    # guarantee that the dictionary will be recorded, so replay may not work.
    if 'accept-encoding' in headers:
      accept_encoding = headers['accept-encoding']
      accept_encoding = accept_encoding.replace('sdch', '')
      # Strip lzma so Opera's requests matches archives recorded using Chrome.
      accept_encoding = accept_encoding.replace('lzma', '')
      stripped_encodings = [e.strip() for e in accept_encoding.split(',')]
      accept_encoding = ','.join(filter(bool, stripped_encodings))
      headers['accept-encoding'] = accept_encoding
    undesirable_keys = [
        'accept', 'accept-charset', 'accept-language', 'cache-control',
        'connection', 'cookie', 'keep-alive', 'method',
        'referer', 'scheme', 'url', 'version', 'user-agent', 'proxy-connection',
        'x-chrome-variations', 'x-client-data']
    return sorted([(k, v) for k, v in headers.items()
                   if k.lower() not in undesirable_keys])

  def is_conditional(self):
    """Return list of headers that match conditional headers."""
    for header in self.CONDITIONAL_HEADERS:
      if header in self.headers:
        return True
    return False

  def create_request_without_conditions(self):
    stripped_headers = dict((k, v) for k, v in self.headers.iteritems()
                            if k.lower() not in self.CONDITIONAL_HEADERS)
    return ArchivedHttpRequest(
        self.command, self.host, self.full_path, self.request_body,
        stripped_headers, self.is_ssl)

class ArchivedHttpResponse(object):
  """All the data needed to recreate all HTTP response.

  Upon creation, the headers are "trimmed" (i.e. edited or dropped).
  The original headers are saved to self.original_headers, while the
  trimmed ones are used to allow responses to match in a wider variety
  of playback situations.

  For pickling, 'original_headers' are stored in the archive.  For unpickling
  the headers are trimmed again. That allows for changes to the trim
  function and can help with debugging.
  """

  # CHUNK_EDIT_SEPARATOR is used to edit and view text content.
  # It is not sent in responses. It is added by get_data_as_text()
  # and removed by set_data().
  CHUNK_EDIT_SEPARATOR = '[WEB_PAGE_REPLAY_CHUNK_BOUNDARY]'

  # DELAY_EDIT_SEPARATOR is used to edit and view server delays.
  DELAY_EDIT_SEPARATOR = ('\n[WEB_PAGE_REPLAY_EDIT_ARCHIVE --- '
                          'Delays are above. Response content is below.]\n')

  # This date was used in deterministic.js prior to switching to recorded
  # request time.  See https://github.com/chromium/web-page-replay/issues/71
  # for details.
  DEFAULT_REQUEST_TIME = datetime.datetime(2008, 2, 29, 2, 26, 8, 254000)

  def __init__(self, version, status, reason, headers, response_data,
               delays=None, request_time=None):
    """Initialize an ArchivedHttpResponse.

    Args:
      version: HTTP protocol version used by server.
          10 for HTTP/1.0, 11 for HTTP/1.1 (same as httplib).
      status: Status code returned by server (e.g. 200).
      reason: Reason phrase returned by server (e.g. "OK").
      headers: list of (header, value) tuples.
      response_data: list of content chunks.
          Concatenating the chunks gives the complete contents
          (i.e. the chunks do not have any lengths or delimiters).
          Do not include the final, zero-length chunk that marks the end.
      delays: dict of (ms) delays for 'connect', 'headers' and 'data'.
          e.g. {'connect': 50, 'headers': 150, 'data': [0, 10, 10]}
          connect - The time to connect to the server.
            Each resource has a value because Replay's record mode captures it.
            This includes the time for the SYN and SYN/ACK (1 rtt).
          headers - The time elapsed between the TCP connect and the headers.
            This typically includes all the server-time to generate a response.
          data - If the response is chunked, these are the times for each chunk.
    """
    self.version = version
    self.status = status
    self.reason = reason
    self.original_headers = headers
    self.headers = self._TrimHeaders(headers)
    self.response_data = response_data
    self.delays = delays
    self.fix_delays()
    self.request_time = (
        request_time or ArchivedHttpResponse.DEFAULT_REQUEST_TIME
    )

  def fix_delays(self):
    """Initialize delays, or check the number of data delays."""
    expected_num_delays = len(self.response_data)
    if not self.delays:
      self.delays = {
          'connect': 0,
          'headers': 0,
          'data': [0] * expected_num_delays
          }
    else:
      num_delays = len(self.delays['data'])
      if num_delays != expected_num_delays:
        raise HttpArchiveException(
            'Server delay length mismatch: %d (expected %d): %s',
            num_delays, expected_num_delays, self.delays['data'])

  @classmethod
  def _TrimHeaders(cls, headers):
    """Removes headers that are known to cause problems during replay.

    These headers are removed for the following reasons:
    - content-security-policy: Causes problems with script injection.
    """
    undesirable_keys = ['content-security-policy']
    return [(k, v) for k, v in headers if k.lower() not in undesirable_keys]

  def __repr__(self):
    return repr((self.version, self.status, self.reason, sorted(self.headers),
                 self.response_data, self.request_time))

  def __hash__(self):
    """Return a integer hash to use for hashed collections including dict."""
    return hash(repr(self))

  def __eq__(self, other):
    """Define the __eq__ method to match the hash behavior."""
    return repr(self) == repr(other)

  def __setstate__(self, state):
    """Influence how to unpickle.

    "original_headers" are the original request headers.
    "headers" are the trimmed headers used for replaying responses.

    Args:
      state: a dictionary for __dict__
    """
    if 'server_delays' in state:
      state['delays'] = {
          'connect': 0,
          'headers': 0,
          'data': state['server_delays']
          }
      del state['server_delays']
    elif 'delays' not in state:
      state['delays'] = None
    # Set to date that was hardcoded in deterministic.js originally.
    state.setdefault('request_time', ArchivedHttpResponse.DEFAULT_REQUEST_TIME)
    state['original_headers'] = state['headers']
    state['headers'] = self._TrimHeaders(state['original_headers'])
    self.__dict__.update(state)
    self.fix_delays()

  def __getstate__(self):
    """Influence how to pickle.

    Returns:
      a dict to use for pickling
    """
    state = self.__dict__.copy()
    state['headers'] = state['original_headers']
    del state['original_headers']
    return state

  def get_header(self, key, default=None):
    for k, v in self.headers:
      if key.lower() == k.lower():
        return v
    return default

  def set_header(self, key, value):
    for i, (k, v) in enumerate(self.headers):
      if key == k:
        self.headers[i] = (key, value)
        return
    self.headers.append((key, value))

  def remove_header(self, key):
    for i, (k, v) in enumerate(self.headers):
      if key.lower() == k.lower():
        self.headers.pop(i)
        return

  @staticmethod
  def _get_epoch_seconds(date_str):
    """Return the epoch seconds of a date header.

    Args:
      date_str: a date string (e.g. "Thu, 01 Dec 1994 16:00:00 GMT")
    Returns:
      epoch seconds as a float
    """
    date_tuple = email.utils.parsedate(date_str)
    if date_tuple:
      return calendar.timegm(date_tuple)
    return None

  def update_date(self, date_str, now=None):
    """Return an updated date based on its delta from the "Date" header.

    For example, if |date_str| is one week later than the "Date" header,
    then the returned date string is one week later than the current date.

    Args:
      date_str: a date string (e.g. "Thu, 01 Dec 1994 16:00:00 GMT")
    Returns:
      a date string
    """
    date_seconds = self._get_epoch_seconds(self.get_header('date'))
    header_seconds = self._get_epoch_seconds(date_str)
    if date_seconds and header_seconds:
      updated_seconds = header_seconds + (now or time.time()) - date_seconds
      return email.utils.formatdate(updated_seconds, usegmt=True)
    return date_str

  def is_gzip(self):
    return self.get_header('content-encoding') == 'gzip'

  def is_compressed(self):
    return self.get_header('content-encoding') in ('gzip', 'deflate')

  def is_chunked(self):
    return self.get_header('transfer-encoding') == 'chunked'

  def get_data_as_chunks(self):
    """Return content as a list of strings, each corresponding to a chunk.

    Uncompresses the chunks, if needed.
    """
    content_type = self.get_header('content-type')
    if (not content_type or
        not (content_type.startswith('text/') or
             content_type == 'application/x-javascript' or
             content_type.startswith('application/json'))):
      return None
    if self.is_compressed():
      return httpzlib.uncompress_chunks(self.response_data, self.is_gzip())
    else:
      return self.response_data

  def get_data_as_text(self):
    """Return content as a single string.

    Uncompresses and concatenates chunks with CHUNK_EDIT_SEPARATOR.
    """
    return self.CHUNK_EDIT_SEPARATOR.join(self.get_data_as_chunks())

  def get_delays_as_text(self):
    """Return delays as editable text."""
    return json.dumps(self.delays, indent=2)

  def get_response_as_text(self):
    """Returns response content as a single string.

    Server delays are separated on a per-chunk basis. Delays are in seconds.
    Response content begins after DELAY_EDIT_SEPARATOR
    """
    data = self.get_data_as_text()
    if data is None:
      logging.warning('Data can not be represented as text.')
      data = ''
    delays = self.get_delays_as_text()
    return self.DELAY_EDIT_SEPARATOR.join((delays, data))

  def set_data_from_chunks(self, text_chunks):
    """Inverse of get_data_as_chunks().

    Compress, if needed.
    """
    if self.is_compressed():
      self.response_data = httpzlib.compress_chunks(text_chunks, self.is_gzip())
    else:
      self.response_data = text_chunks
    if not self.is_chunked():
      content_length = sum(len(c) for c in self.response_data)
      self.set_header('content-length', str(content_length))

  def set_data(self, text):
    """Inverse of get_data_as_text().

    Split on CHUNK_EDIT_SEPARATOR and compress if needed.
    """
    self.set_data_from_chunks(text.split(self.CHUNK_EDIT_SEPARATOR))

  def set_delays(self, delays_text):
    """Inverse of get_delays_as_text().

    Args:
      delays_text: JSON encoded text such as the following:
          {
            connect: 80,
            headers: 80,
            data: [6, 55, 0]
          }
        Times are in milliseconds.
        Each data delay corresponds with one response_data value.
    """
    try:
      self.delays = json.loads(delays_text)
    except (ValueError, KeyError) as e:
      logging.critical('Unable to parse delays %s: %s', delays_text, e)
    self.fix_delays()

  def set_response_from_text(self, text):
    """Inverse of get_response_as_text().

    Modifies the state of the archive according to the textual representation.
    """
    try:
      delays, data = text.split(self.DELAY_EDIT_SEPARATOR)
    except ValueError:
      logging.critical(
          'Error parsing text representation. Skipping edits.')
      return
    self.set_delays(delays)
    self.set_data(data)


def create_response(status, reason=None, headers=None, body=None):
  """Convenience method for creating simple ArchivedHttpResponse objects."""
  if reason is None:
    reason = httplib.responses.get(status, 'Unknown')
  if headers is None:
    headers = [('content-type', 'text/plain')]
  if body is None:
    body = "%s %s" % (status, reason)
  return ArchivedHttpResponse(11, status, reason, headers, [body])


def main():
  class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    def format_description(self, description):
      if description:
        return description + '\n'
      else:
        return ''

  option_parser = optparse.OptionParser(
      usage='%prog [ls|cat|edit|stats|merge] [options] replay_file(s)',
      formatter=PlainHelpFormatter(),
      description=__doc__,
      epilog='http://code.google.com/p/web-page-replay/')

  option_parser.add_option('-c', '--command', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this command.')
  option_parser.add_option('-o', '--host', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this host.')
  option_parser.add_option('-p', '--full_path', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this full path.')
  option_parser.add_option('-f', '--merged_file', default=None,
        action='store',
        type='string',
        help='The output file to use when using the merge command.')

  options, args = option_parser.parse_args()

  # Merge command expects an umlimited number of archives.
  if len(args) < 2:
    print 'args: %s' % args
    option_parser.error('Must specify a command and replay_file')

  command = args[0]
  replay_file = args[1]

  if not os.path.exists(replay_file):
    option_parser.error('Replay file "%s" does not exist' % replay_file)

  http_archive = HttpArchive.Load(replay_file)
  if command == 'ls':
    print http_archive.ls(options.command, options.host, options.full_path)
  elif command == 'cat':
    print http_archive.cat(options.command, options.host, options.full_path)
  elif command == 'stats':
    print http_archive.stats(options.command, options.host, options.full_path)
  elif command == 'merge':
    if not options.merged_file:
      print 'Error: Must specify a merged file name (use --merged_file)'
      return
    http_archive.merge(options.merged_file, args[2:])
  elif command == 'edit':
    http_archive.edit(options.command, options.host, options.full_path)
    http_archive.Persist(replay_file)
  else:
    option_parser.error('Unknown command "%s"' % command)
  return 0


if __name__ == '__main__':
  sys.exit(main())
