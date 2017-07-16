# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Finds browsers that can be controlled by telemetry."""

import logging
import operator

from telemetry import decorators
from telemetry.internal.backends.chrome import android_browser_finder
from telemetry.internal.backends.chrome import cros_browser_finder
from telemetry.internal.backends.chrome import desktop_browser_finder
from telemetry.internal.backends.chrome import ios_browser_finder
from telemetry.internal.browser import browser_finder_exceptions
from telemetry.internal.platform import device_finder

BROWSER_FINDERS = [
  desktop_browser_finder,
  android_browser_finder,
  cros_browser_finder,
  ios_browser_finder,
  ]


def FindAllBrowserTypes(options):
  return reduce(operator.add,
                [bf.FindAllBrowserTypes(options) for bf in BROWSER_FINDERS])


@decorators.Cache
def FindBrowser(options):
  """Finds the best PossibleBrowser object given a BrowserOptions object.

  Args:
    A BrowserOptions object.

  Returns:
    A PossibleBrowser object.

  Raises:
    BrowserFinderException: Options improperly set, or an error occurred.
  """
  if options.__class__.__name__ == '_FakeBrowserFinderOptions':
    return options.fake_possible_browser
  if options.browser_type == 'exact' and options.browser_executable == None:
    raise browser_finder_exceptions.BrowserFinderException(
        '--browser=exact requires --browser-executable to be set.')
  if options.browser_type != 'exact' and options.browser_executable != None:
    raise browser_finder_exceptions.BrowserFinderException(
        '--browser-executable requires --browser=exact.')

  if options.browser_type == 'cros-chrome' and options.cros_remote == None:
    raise browser_finder_exceptions.BrowserFinderException(
        'browser_type=cros-chrome requires cros_remote be set.')
  if (options.browser_type != 'cros-chrome' and
      options.browser_type != 'cros-chrome-guest' and
      options.cros_remote != None):
    raise browser_finder_exceptions.BrowserFinderException(
        '--remote requires --browser=cros-chrome or cros-chrome-guest.')

  devices = device_finder.GetDevicesMatchingOptions(options)
  browsers = []
  default_browsers = []
  for device in devices:
    for finder in BROWSER_FINDERS:
      if(options.browser_type and options.browser_type != 'any' and
         options.browser_type not in finder.FindAllBrowserTypes(options)):
        continue
      curr_browsers = finder.FindAllAvailableBrowsers(options, device)
      new_default_browser = finder.SelectDefaultBrowser(curr_browsers)
      if new_default_browser:
        default_browsers.append(new_default_browser)
      browsers.extend(curr_browsers)

  if options.browser_type == None:
    if default_browsers:
      default_browser = sorted(default_browsers,
                               key=lambda b: b.last_modification_time())[-1]

      logging.warning('--browser omitted. Using most recent local build: %s' %
                      default_browser.browser_type)
      default_browser.UpdateExecutableIfNeeded()
      return default_browser

    if len(browsers) == 1:
      logging.warning('--browser omitted. Using only available browser: %s' %
                      browsers[0].browser_type)
      browsers[0].UpdateExecutableIfNeeded()
      return browsers[0]

    raise browser_finder_exceptions.BrowserTypeRequiredException(
        '--browser must be specified. Available browsers:\n%s' %
        '\n'.join(sorted(set([b.browser_type for b in browsers]))))

  if options.browser_type == 'any':
    types = FindAllBrowserTypes(options)
    def CompareBrowsersOnTypePriority(x, y):
      x_idx = types.index(x.browser_type)
      y_idx = types.index(y.browser_type)
      return x_idx - y_idx
    browsers.sort(CompareBrowsersOnTypePriority)
    if len(browsers) >= 1:
      browsers[0].UpdateExecutableIfNeeded()
      return browsers[0]
    else:
      return None

  matching_browsers = [b for b in browsers
      if b.browser_type == options.browser_type and
      b.SupportsOptions(options.browser_options)]

  chosen_browser = None
  if len(matching_browsers) == 1:
    chosen_browser = matching_browsers[0]
  elif len(matching_browsers) > 1:
    logging.warning('Multiple browsers of the same type found: %s' % (
                    repr(matching_browsers)))
    chosen_browser = sorted(matching_browsers,
                            key=lambda b: b.last_modification_time())[-1]

  if chosen_browser:
    logging.info('Chose browser: %s' % (repr(chosen_browser)))
    chosen_browser.UpdateExecutableIfNeeded()

  return chosen_browser


@decorators.Cache
def GetAllAvailableBrowsers(options, device):
  """Returns a list of available browsers on the device.

  Args:
    options: A BrowserOptions object.
    device: The target device, which can be None.

  Returns:
    A list of browser instances.

  Raises:
    BrowserFinderException: Options are improperly set, or an error occurred.
  """
  if not device:
    return []
  possible_browsers = []
  for browser_finder in BROWSER_FINDERS:
    possible_browsers.extend(
      browser_finder.FindAllAvailableBrowsers(options, device))
  return possible_browsers


@decorators.Cache
def GetAllAvailableBrowserTypes(options):
  """Returns a list of available browser types.

  Args:
    options: A BrowserOptions object.

  Returns:
    A list of browser type strings.

  Raises:
    BrowserFinderException: Options are improperly set, or an error occurred.
  """
  devices = device_finder.GetDevicesMatchingOptions(options)
  possible_browsers = []
  for device in devices:
    possible_browsers.extend(GetAllAvailableBrowsers(options, device))
  type_list = set([browser.browser_type for browser in possible_browsers])
  # The reference build should be available for mac, linux and win, but the
  # desktop browser finder won't return it in the list of browsers.
  for browser in possible_browsers:
    if (browser.target_os == 'darwin' or browser.target_os.startswith('linux')
        or browser.target_os.startswith('win')):
      type_list.add('reference')
      break
  type_list = list(type_list)
  type_list.sort()
  return type_list
