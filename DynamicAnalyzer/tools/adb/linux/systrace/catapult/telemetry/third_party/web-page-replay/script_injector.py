#!/usr/bin/env python
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Inject javascript into html page source code."""

import datetime
import logging
import os
import re
import util
import third_party.jsmin as jsmin

DOCTYPE_RE = re.compile(r'^.{,256}?(<!--.*-->)?.{,256}?<!doctype html>',
                        re.IGNORECASE | re.DOTALL)
HTML_RE = re.compile(r'^.{,256}?(<!--.*-->)?.{,256}?<html.*?>',
                     re.IGNORECASE | re.DOTALL)
HEAD_RE = re.compile(r'^.{,256}?(<!--.*-->)?.{,256}?<head.*?>',
                     re.IGNORECASE | re.DOTALL)

# Occurences of this marker in injected scripts will be replaced with
# recording time in javascripts' Date().toValue() format.  This allows
# to properly set deterministic date in JS code.  See
# https://github.com/chromium/web-page-replay/issues/71 for details.
TIME_SEED_MARKER = '{{WPR_TIME_SEED_TIMESTAMP}}'


def GetScriptInjector(scripts):
  """Loads |scripts| from disk and returns an injector of their content."""
  lines = []
  if scripts:
    if not isinstance(scripts, list):
      scripts = scripts.split(',')
    for script in scripts:
      if os.path.exists(script):
        with open(script) as f:
          lines.extend(f.read())
      elif util.resource_exists(script):
        lines.extend(util.resource_string(script))
      else:
        raise Exception('Script does not exist: %s', script)

  script_template = jsmin.jsmin(''.join(lines), quote_chars="'\"`")
  def injector(record_time):
    delta = record_time - datetime.datetime(1970, 1, 1)
    js_timestamp = \
        int(delta.total_seconds()) * 1000 + delta.microseconds / 1000
    return script_template.replace(TIME_SEED_MARKER, str(js_timestamp))
  return injector


def _IsHtmlContent(content):
  content = content.strip()
  return content.startswith('<') and content.endswith('>')


def InjectScript(text_chunks, content_type, script_to_inject):
  """Inject |script_to_inject| into |content| if |content_type| is 'text/html'.

  Inject |script_to_inject| into |text_chunks| immediately after <head>,
  <html> or <!doctype html>, if one of them is found. Otherwise, inject at
  the beginning.

  Returns:
    text_chunks, already_injected
    |text_chunks| is the new content if script is injected, otherwise
      the original.  If the script was injected, exactly one chunk in
      |text_chunks| will have changed.
    |just_injected| indicates if |script_to_inject| was just injected in
      the content.
  """
  if not content_type or content_type != 'text/html':
    return text_chunks, False
  content = "".join(text_chunks)
  if not content or not _IsHtmlContent(content) or script_to_inject in content:
    return text_chunks, False
  for regexp in (HEAD_RE, HTML_RE, DOCTYPE_RE):
    matchobj = regexp.search(content)
    if matchobj:
      pos = matchobj.end(0)
      for i, chunk in enumerate(text_chunks):
        if pos <= len(chunk):
          result = text_chunks[:]
          result[i] = '%s<script>%s</script>%s' % (chunk[0:pos],
                                                   script_to_inject,
                                                   chunk[pos:])
          return result, True
        pos -= len(chunk)
  result = text_chunks[:]
  result[0] = '<script>%s</script>%s' % (script_to_inject,
                                         text_chunks[0])
  logging.warning('Inject at the very beginning, because no tag of '
                  '<head>, <html> or <!doctype html> is found.')
  return result, True
