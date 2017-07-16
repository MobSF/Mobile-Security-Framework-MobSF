# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# pylint: disable=protected-access

import datetime
import functools
import os
import inspect
import types
import warnings


def Cache(obj):
  """Decorator for caching read-only properties.

  Example usage (always returns the same Foo instance):
    @Cache
    def CreateFoo():
      return Foo()

  If CreateFoo() accepts parameters, a separate cached value is maintained
  for each unique parameter combination.

  Cached methods maintain their cache for the lifetime of the /instance/, while
  cached functions maintain their cache for the lifetime of the /module/.
  """
  @functools.wraps(obj)
  def Cacher(*args, **kwargs):
    cacher = args[0] if inspect.getargspec(obj).args[:1] == ['self'] else obj
    cacher.__cache = cacher.__cache if hasattr(cacher, '__cache') else {}
    key = str(obj) + str(args) + str(kwargs)
    if key not in cacher.__cache:
      cacher.__cache[key] = obj(*args, **kwargs)
    return cacher.__cache[key]
  return Cacher


class Deprecated(object):

  def __init__(self, year, month, day, extra_guidance=''):
    self._date_of_support_removal = datetime.date(year, month, day)
    self._extra_guidance = extra_guidance

  def _DisplayWarningMessage(self, target):
    target_str = ''
    if isinstance(target, types.FunctionType):
      target_str = 'Function %s' % target.__name__
    else:
      target_str = 'Class %s' % target.__name__
    warnings.warn('%s is deprecated. It will no longer be supported on %s. '
                  'Please remove it or switch to an alternative before '
                  'that time. %s\n'
                  % (target_str,
                     self._date_of_support_removal.strftime('%B %d, %Y'),
                     self._extra_guidance),
                  stacklevel=self._ComputeStackLevel())

  def _ComputeStackLevel(self):
    this_file, _ = os.path.splitext(__file__)
    frame = inspect.currentframe()
    i = 0
    while True:
      filename = frame.f_code.co_filename
      if not filename.startswith(this_file):
        return i
      frame = frame.f_back
      i += 1

  def __call__(self, target):
    if isinstance(target, types.FunctionType):
      @functools.wraps(target)
      def wrapper(*args, **kwargs):
        self._DisplayWarningMessage(target)
        return target(*args, **kwargs)
      return wrapper
    elif inspect.isclass(target):
      original_ctor = target.__init__

      # We have to handle case original_ctor is object.__init__ separately
      # since object.__init__ does not have __module__ defined, which
      # cause functools.wraps() to raise exception.
      if original_ctor == object.__init__:
        def new_ctor(*args, **kwargs):
          self._DisplayWarningMessage(target)
          return original_ctor(*args, **kwargs)
      else:
        @functools.wraps(original_ctor)
        def new_ctor(*args, **kwargs):
          self._DisplayWarningMessage(target)
          return original_ctor(*args, **kwargs)

      target.__init__ = new_ctor
      return target
    else:
      raise TypeError('@Deprecated is only applicable to functions or classes')


def Disabled(*args):
  """Decorator for disabling tests/benchmarks.


  If args are given, the test will be disabled if ANY of the args match the
  browser type, OS name or OS version:
    @Disabled('canary')        # Disabled for canary browsers
    @Disabled('win')           # Disabled on Windows.
    @Disabled('win', 'linux')  # Disabled on both Windows and Linux.
    @Disabled('mavericks')     # Disabled on Mac Mavericks (10.9) only.
    @Disabled('all')  # Unconditionally disabled.
  """
  def _Disabled(func):
    disabled_attr_name = DisabledAttributeName(func)
    if not hasattr(func, disabled_attr_name):
      setattr(func, disabled_attr_name, set())
    disabled_set = getattr(func, disabled_attr_name)
    disabled_set.update(disabled_strings)
    setattr(func, disabled_attr_name, disabled_set)
    return func
  assert args, (
      "@Disabled(...) requires arguments. Use @Disabled('all') if you want to "
      'unconditionally disable the test.')
  assert not callable(args[0]), 'Please use @Disabled(..).'
  disabled_strings = list(args)
  for disabled_string in disabled_strings:
    # TODO(tonyg): Validate that these strings are recognized.
    assert isinstance(disabled_string, str), '@Disabled accepts a list of strs'
  return _Disabled


def Enabled(*args):
  """Decorator for enabling tests/benchmarks.

  The test will be enabled if ANY of the args match the browser type, OS name
  or OS version:
    @Enabled('canary')        # Enabled only for canary browsers
    @Enabled('win')           # Enabled only on Windows.
    @Enabled('win', 'linux')  # Enabled only on Windows or Linux.
    @Enabled('mavericks')     # Enabled only on Mac Mavericks (10.9).
  """
  def _Enabled(func):
    enabled_attr_name = EnabledAttributeName(func)
    if not hasattr(func, enabled_attr_name):
      setattr(func, enabled_attr_name, set())
    enabled_set = getattr(func, enabled_attr_name)
    enabled_set.update(enabled_strings)
    setattr(func, enabled_attr_name, enabled_set)
    return func
  assert args, '@Enabled(..) requires arguments'
  assert not callable(args[0]), 'Please use @Enabled(..).'
  enabled_strings = list(args)
  for enabled_string in enabled_strings:
    # TODO(tonyg): Validate that these strings are recognized.
    assert isinstance(enabled_string, str), '@Enabled accepts a list of strs'
  return _Enabled


def Owner(emails=None, component=None):
  """Decorator for specifying the owner of a benchmark."""
  def _Owner(func):
    owner_attr_name = OwnerAttributeName(func)
    assert inspect.isclass(func), '@Owner(...) can only be used on classes'
    if not hasattr(func, owner_attr_name):
      setattr(func, owner_attr_name, {})
    owner_dict = getattr(func, owner_attr_name)
    if emails:
      assert 'emails' not in owner_dict, 'emails can only be set once'
      owner_dict['emails'] = emails
    if component:
      assert 'component' not in owner_dict, 'component can only be set once'
      owner_dict['component'] = component
    setattr(func, owner_attr_name, owner_dict)
    return func
  help_text = '@Owner(...) requires emails and/or a component'
  assert emails or component, help_text
  if emails:
    assert isinstance(emails, list), 'emails must be a list of strs'
    for e in emails:
      assert isinstance(e, str), 'emails must be a list of strs'
  return _Owner


# TODO(dpranke): Remove if we don't need this.
def Isolated(*args):
  """Decorator for noting that tests must be run in isolation.

  The test will be run by itself (not concurrently with any other tests)
  if ANY of the args match the browser type, OS name, or OS version."""
  def _Isolated(func):
    if not isinstance(func, types.FunctionType):
      func._isolated_strings = isolated_strings
      return func
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      func(*args, **kwargs)
    wrapper._isolated_strings = isolated_strings
    return wrapper
  if len(args) == 1 and callable(args[0]):
    isolated_strings = []
    return _Isolated(args[0])
  isolated_strings = list(args)
  for isolated_string in isolated_strings:
    # TODO(tonyg): Validate that these strings are recognized.
    assert isinstance(isolated_string, str), 'Isolated accepts a list of strs'
  return _Isolated


# TODO(nednguyen): Remove this and have call site just use ShouldSkip directly.
def IsEnabled(test, possible_browser):
  """Returns True iff |test| is enabled given the |possible_browser|.

  Use to respect the @Enabled / @Disabled decorators.

  Args:
    test: A function or class that may contain _disabled_strings and/or
          _enabled_strings attributes.
    possible_browser: A PossibleBrowser to check whether |test| may run against.
  """
  should_skip, msg = ShouldSkip(test, possible_browser)
  return (not should_skip, msg)


def IsBenchmarkEnabled(benchmark, possible_browser):
  return (not benchmark.ShouldDisable(possible_browser) and
          IsEnabled(benchmark, possible_browser)[0])


def _TestName(test):
  if inspect.ismethod(test):
    # On methods, __name__ is "instancemethod", use __func__.__name__ instead.
    test = test.__func__
  if hasattr(test, '__name__'):
    return test.__name__
  elif hasattr(test, '__class__'):
    return test.__class__.__name__
  return str(test)


def DisabledAttributeName(test):
  name = _TestName(test)
  return '_%s_%s_disabled_strings' % (test.__module__, name)


def GetDisabledAttributes(test):
  disabled_attr_name = DisabledAttributeName(test)
  if not hasattr(test, disabled_attr_name):
    return set()
  return set(getattr(test, disabled_attr_name))


def GetEnabledAttributes(test):
  enabled_attr_name = EnabledAttributeName(test)
  if not hasattr(test, enabled_attr_name):
    return set()
  enabled_strings = set(getattr(test, enabled_attr_name))
  return enabled_strings


def EnabledAttributeName(test):
  name = _TestName(test)
  return '_%s_%s_enabled_strings' % (test.__module__, name)


def OwnerAttributeName(test):
  name = _TestName(test)
  return '_%s_%s_owner' % (test.__module__, name)


def GetEmails(test):
  owner_attr_name = OwnerAttributeName(test)
  owner = getattr(test, owner_attr_name, {})
  if 'emails' in owner:
    return owner['emails']
  return None


def GetComponent(test):
  owner_attr_name = OwnerAttributeName(test)
  owner = getattr(test, owner_attr_name, {})
  if 'component' in owner:
    return owner['component']
  return None


def ShouldSkip(test, possible_browser):
  """Returns whether the test should be skipped and the reason for it."""
  platform_attributes = _PlatformAttributes(possible_browser)

  name = _TestName(test)
  skip = 'Skipping %s (%s) because' % (name, str(test))
  running = 'You are running %r.' % platform_attributes

  disabled_attr_name = DisabledAttributeName(test)
  if hasattr(test, disabled_attr_name):
    disabled_strings = getattr(test, disabled_attr_name)
    if 'all' in disabled_strings:
      return (True, '%s it is unconditionally disabled.' % skip)
    if set(disabled_strings) & set(platform_attributes):
      return (True, '%s it is disabled for %s. %s' %
                      (skip, ' and '.join(disabled_strings), running))

  enabled_attr_name = EnabledAttributeName(test)
  if hasattr(test, enabled_attr_name):
    enabled_strings = getattr(test, enabled_attr_name)
    if 'all' in enabled_strings:
      return False, None  # No arguments to @Enabled means always enable.
    if not set(enabled_strings) & set(platform_attributes):
      return (True, '%s it is only enabled for %s. %s' %
                      (skip, ' or '.join(enabled_strings), running))

  return False, None


def ShouldBeIsolated(test, possible_browser):
  platform_attributes = _PlatformAttributes(possible_browser)
  if hasattr(test, '_isolated_strings'):
    isolated_strings = test._isolated_strings
    if not isolated_strings:
      return True # No arguments to @Isolated means always isolate.
    for isolated_string in isolated_strings:
      if isolated_string in platform_attributes:
        return True
    return False
  return False


def _PlatformAttributes(possible_browser):
  """Returns a list of platform attribute strings."""
  attributes = [a.lower() for a in [
      possible_browser.browser_type,
      possible_browser.platform.GetOSName(),
      possible_browser.platform.GetOSVersionName(),
  ]]
  if possible_browser.supports_tab_control:
    attributes.append('has tabs')
  if 'content-shell' in possible_browser.browser_type:
    attributes.append('content-shell')
  if possible_browser.browser_type == 'reference':
    ref_attributes = []
    for attribute in attributes:
      if attribute != 'reference':
        ref_attributes.append('%s-reference' % attribute)
    attributes.extend(ref_attributes)
  return attributes
