# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import inspect
import logging
import os
import urlparse

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry import story
from telemetry.page import cache_temperature as cache_temperature_module
from telemetry.page import shared_page_state
from telemetry.page import traffic_setting as traffic_setting_module
from telemetry.internal.actions import action_runner as action_runner_module


class Page(story.Story):

  def __init__(self, url, page_set=None, base_dir=None, name='',
               credentials_path=None,
               credentials_bucket=cloud_storage.PUBLIC_BUCKET, tags=None,
               startup_url='', make_javascript_deterministic=True,
               shared_page_state_class=shared_page_state.SharedPageState,
               grouping_keys=None,
               cache_temperature=cache_temperature_module.ANY,
               traffic_setting=traffic_setting_module.NONE,
               platform_specific=False):
    self._url = url

    super(Page, self).__init__(
        shared_page_state_class, name=name, tags=tags,
        is_local=self._scheme in ['file', 'chrome', 'about'],
        make_javascript_deterministic=make_javascript_deterministic,
        grouping_keys=grouping_keys, platform_specific=platform_specific)

    self._page_set = page_set
    # Default value of base_dir is the directory of the file that defines the
    # class of this page instance.
    if base_dir is None:
      base_dir = os.path.dirname(inspect.getfile(self.__class__))
    self._base_dir = base_dir
    self._name = name
    if credentials_path:
      credentials_path = os.path.join(self._base_dir, credentials_path)
      cloud_storage.GetIfChanged(credentials_path, credentials_bucket)
      if not os.path.exists(credentials_path):
        logging.error('Invalid credentials path: %s' % credentials_path)
        credentials_path = None
    self._credentials_path = credentials_path
    self._cache_temperature = cache_temperature
    if cache_temperature != cache_temperature_module.ANY:
      self.grouping_keys['cache_temperature'] = cache_temperature
    if traffic_setting != traffic_setting_module.NONE:
      self.grouping_keys['traffic_setting'] = traffic_setting

    assert traffic_setting in traffic_setting_module.NETWORK_CONFIGS, (
        'Invalid traffic setting: %s' % traffic_setting)
    self._traffic_setting = traffic_setting

    # Whether to collect garbage on the page before navigating & performing
    # page actions.
    self._collect_garbage_before_run = True

    # These attributes can be set dynamically by the page.
    self.synthetic_delays = dict()
    self._startup_url = startup_url
    self.credentials = None
    self.skip_waits = False
    self.script_to_evaluate_on_commit = None
    self._SchemeErrorCheck()

  @property
  def credentials_path(self):
    return self._credentials_path

  @property
  def cache_temperature(self):
    return self._cache_temperature

  @property
  def traffic_setting(self):
    return self._traffic_setting

  @property
  def startup_url(self):
    return self._startup_url

  def _SchemeErrorCheck(self):
    if not self._scheme:
      raise ValueError('Must prepend the URL with scheme (e.g. file://)')

    if self.startup_url:
      startup_url_scheme = urlparse.urlparse(self.startup_url).scheme
      if not startup_url_scheme:
        raise ValueError('Must prepend the URL with scheme (e.g. http://)')
      if startup_url_scheme == 'file':
        raise ValueError('startup_url with local file scheme is not supported')

  def Run(self, shared_state):
    current_tab = shared_state.current_tab
    # Collect garbage from previous run several times to make the results more
    # stable if needed.
    if self._collect_garbage_before_run:
      for _ in xrange(0, 5):
        current_tab.CollectGarbage()
    shared_state.page_test.WillNavigateToPage(self, current_tab)
    shared_state.page_test.RunNavigateSteps(self, current_tab)
    shared_state.page_test.DidNavigateToPage(self, current_tab)
    action_runner = action_runner_module.ActionRunner(
        current_tab, skip_waits=self.skip_waits)
    self.RunPageInteractions(action_runner)

  def RunNavigateSteps(self, action_runner):
    url = self.file_path_url_with_scheme if self.is_file else self.url
    action_runner.Navigate(
        url, script_to_evaluate_on_commit=self.script_to_evaluate_on_commit)

  def RunPageInteractions(self, action_runner):
    """Override this to define custom interactions with the page.
    e.g:
      def RunPageInteractions(self, action_runner):
        action_runner.ScrollPage()
        action_runner.TapElement(text='Next')
    """
    pass

  def AsDict(self):
    """Converts a page object to a dict suitable for JSON output."""
    d = {
        'id': self._id,
        'url': self._url,
    }
    if self._name:
      d['name'] = self._name
    return d

  @property
  def story_set(self):
    return self._page_set

  # TODO(nednguyen, aiolos): deprecate this property.
  @property
  def page_set(self):
    return self._page_set

  @property
  def url(self):
    return self._url

  def GetSyntheticDelayCategories(self):
    result = []
    for delay, options in self.synthetic_delays.items():
      options = '%f;%s' % (options.get('target_duration', 0),
                           options.get('mode', 'static'))
      result.append('DELAY(%s;%s)' % (delay, options))
    return result

  def __lt__(self, other):
    return self.url < other.url

  def __cmp__(self, other):
    x = cmp(self.name, other.name)
    if x != 0:
      return x
    return cmp(self.url, other.url)

  def __str__(self):
    return self.url

  @property
  def _scheme(self):
    return urlparse.urlparse(self.url).scheme

  @property
  def is_file(self):
    """Returns True iff this URL points to a file."""
    return self._scheme == 'file'

  @property
  def file_path(self):
    """Returns the path of the file, stripping the scheme and query string."""
    assert self.is_file
    # Because ? is a valid character in a filename,
    # we have to treat the URL as a non-file by removing the scheme.
    parsed_url = urlparse.urlparse(self.url[7:])
    return os.path.normpath(os.path.join(
        self._base_dir, parsed_url.netloc + parsed_url.path))

  @property
  def base_dir(self):
    return self._base_dir

  @property
  def file_path_url(self):
    """Returns the file path, including the params, query, and fragment."""
    assert self.is_file
    file_path_url = os.path.normpath(
        os.path.join(self._base_dir, self.url[7:]))
    # Preserve trailing slash or backslash.
    # It doesn't matter in a file path, but it does matter in a URL.
    if self.url.endswith('/'):
      file_path_url += os.sep
    return file_path_url

  @property
  def file_path_url_with_scheme(self):
    return 'file://' + self.file_path_url

  @property
  def serving_dir(self):
    if not self.is_file:
      return None
    file_path = os.path.realpath(self.file_path)
    if os.path.isdir(file_path):
      return file_path
    else:
      return os.path.dirname(file_path)

  @property
  def display_name(self):
    if self.name:
      return self.name
    if self.page_set is None or not self.is_file:
      return self.url
    all_urls = [p.url.rstrip('/') for p in self.page_set if p.is_file]
    common_prefix = os.path.dirname(os.path.commonprefix(all_urls))
    return self.url[len(common_prefix):].strip('/')
