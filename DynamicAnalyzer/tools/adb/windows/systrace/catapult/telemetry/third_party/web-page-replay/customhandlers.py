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

"""Handle special HTTP requests.

/web-page-replay-generate-[RESPONSE_CODE]
  - Return the given RESPONSE_CODE.
/web-page-replay-post-image-[FILENAME]
  - Save the posted image to local disk.
/web-page-replay-command-[record|replay|status]
  - Optional. Enable by calling custom_handlers.add_server_manager_handler(...).
  - Change the server mode to either record or replay.
    + When switching to record, the http_archive is cleared.
    + When switching to replay, the http_archive is maintained.
"""

import base64
import httparchive
import json
import logging
import os

COMMON_URL_PREFIX = '/web-page-replay-'
COMMAND_URL_PREFIX = COMMON_URL_PREFIX + 'command-'
GENERATOR_URL_PREFIX = COMMON_URL_PREFIX + 'generate-'
POST_IMAGE_URL_PREFIX = COMMON_URL_PREFIX + 'post-image-'
IMAGE_DATA_PREFIX = 'data:image/png;base64,'


def SimpleResponse(status):
  """Return a ArchivedHttpResponse with |status| code and a simple text body."""
  return httparchive.create_response(status)


def JsonResponse(data):
  """Return a ArchivedHttpResponse with |data| encoded as json in the body."""
  status = 200
  reason = 'OK'
  headers = [('content-type', 'application/json')]
  body = json.dumps(data)
  return httparchive.create_response(status, reason, headers, body)


class CustomHandlers(object):

  def __init__(self, options, http_archive):
    """Initialize CustomHandlers.

    Args:
      options: original options passed to the server.
      http_archive: reference to the HttpArchive object.
    """
    self.server_manager = None
    self.options = options
    self.http_archive = http_archive
    self.handlers = [
        (GENERATOR_URL_PREFIX, self.get_generator_url_response_code)]
    # screenshot_dir is a path to which screenshots are saved.
    if options.screenshot_dir:
      if not os.path.exists(options.screenshot_dir):
        try:
          os.makedirs(options.screenshot_dir)
        except IOError:
          logging.error('Unable to create screenshot dir: %s',
                         options.screenshot_dir)
          options.screenshot_dir = None
      if options.screenshot_dir:
        self.screenshot_dir = options.screenshot_dir
        self.handlers.append(
            (POST_IMAGE_URL_PREFIX, self.handle_possible_post_image))

  def handle(self, request):
    """Dispatches requests to matching handlers.

    Args:
      request: an http request
    Returns:
      ArchivedHttpResponse or None.
    """
    for prefix, handler in self.handlers:
      if request.full_path.startswith(prefix):
        return handler(request, request.full_path[len(prefix):])
    return None

  def get_generator_url_response_code(self, request, url_suffix):
    """Parse special generator URLs for the embedded response code.

    Args:
      request: an ArchivedHttpRequest instance
      url_suffix: string that is after the handler prefix (e.g. 304)
    Returns:
      On a match, an ArchivedHttpResponse.
      Otherwise, None.
    """
    del request
    try:
      response_code = int(url_suffix)
      return SimpleResponse(response_code)
    except ValueError:
      return None

  def handle_possible_post_image(self, request, url_suffix):
    """If sent, saves embedded image to local directory.

    Expects a special url containing the filename. If sent, saves the base64
    encoded request body as a PNG image locally. This feature is enabled by
    passing in screenshot_dir to the initializer for this class.

    Args:
      request: an ArchivedHttpRequest instance
      url_suffix: string that is after the handler prefix (e.g. 'foo.png')
    Returns:
      On a match, an ArchivedHttpResponse.
      Otherwise, None.
    """
    basename = url_suffix
    if not basename:
      return None

    data = request.request_body
    if not data.startswith(IMAGE_DATA_PREFIX):
      logging.error('Unexpected image format for: %s', basename)
      return SimpleResponse(400)

    data = data[len(IMAGE_DATA_PREFIX):]
    png = base64.b64decode(data)
    filename = os.path.join(self.screenshot_dir,
                            '%s-%s.png' % (request.host, basename))
    if not os.access(self.screenshot_dir, os.W_OK):
      logging.error('Unable to write to: %s', filename)
      return SimpleResponse(400)

    with file(filename, 'w') as f:
      f.write(png)
    return SimpleResponse(200)

  def add_server_manager_handler(self, server_manager):
    """Add the ability to change the server mode (e.g. to record mode).
    Args:
      server_manager: a servermanager.ServerManager instance.
    """
    self.server_manager = server_manager
    self.handlers.append(
        (COMMAND_URL_PREFIX, self.handle_server_manager_command))

  def handle_server_manager_command(self, request, url_suffix):
    """Parse special URLs for the embedded server manager command.

    Clients like webpagetest.org can use URLs of this form to change
    the replay server from record mode to replay mode.

    This handler is not in the default list of handlers. Call
    add_server_manager_handler to add it.

    In the future, this could be expanded to save or serve archive files.

    Args:
      request: an ArchivedHttpRequest instance
      url_suffix: string that is after the handler prefix (e.g. 'record')
    Returns:
      On a match, an ArchivedHttpResponse.
      Otherwise, None.
    """
    command = url_suffix
    if command == 'record':
      self.server_manager.SetRecordMode()
      return SimpleResponse(200)
    elif command == 'replay':
      self.server_manager.SetReplayMode()
      return SimpleResponse(200)
    elif command == 'status':
      status = {}
      is_record_mode = self.server_manager.IsRecordMode()
      status['is_record_mode'] = is_record_mode
      status['options'] = json.loads(str(self.options))
      archive_stats = self.http_archive.stats()
      if archive_stats:
        status['archive_stats'] = json.loads(archive_stats)
      return JsonResponse(status)
    elif command == 'exit':
      self.server_manager.should_exit = True
      return SimpleResponse(200)
    elif command == 'log':
      logging.info('log command: %s', str(request.request_body)[:1000000])
      return SimpleResponse(200)
    return None
