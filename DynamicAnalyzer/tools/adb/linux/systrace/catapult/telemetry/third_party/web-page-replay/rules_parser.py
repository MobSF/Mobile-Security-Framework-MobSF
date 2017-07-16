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

r"""Rules parser.

The input syntax is:
  [{"comment": ignored_value},
   {"rule_class_name1": {"arg1": value, "arg2": value, ...}},
   {"rule_class_name2": {"arg1": value, "arg2": value, ...}},
   ...]
E.g.:
  [{"comment": "this text is ignored"},
   {"SendStatus": {"url": "example\\.com/ss.*", "status": 204}},
   {"ModifyUrl": {"url": "(example\\.com)(/.*)", "new_url": "{1}"}}
  ]
"""

import json
import re


class Error(Exception):
  pass


class Rules(object):

  """A parsed sequence of Rule objects."""

  def __init__(self, file_obj=None, allowed_imports=None):
    """Initializes from the given file object.

    Args:
      file_obj: A file object.
      allowed_imports: A set of strings, defaults to {'rules'}.
        Use {'*'} to allow any import path.
    """
    if allowed_imports is None:
      allowed_imports = {'rules'}
    self._rules = [] if file_obj is None else _Load(file_obj, allowed_imports)

  def Contains(self, rule_type_name):
    """Returns true if any rule matches the given type name.

    Args:
      rule_type_name: a string.
    Returns:
      True if any rule matches, else False.
    """
    return any(rule for rule in self._rules if rule.IsType(rule_type_name))

  def Find(self, rule_type_name):
    """Returns a _Rule object containing all rules with the given type name.

    Args:
      rule_type_name: a string.
    Returns:
      A callable object that expects two arguments:
        request: the httparchive ArchivedHttpRequest
        response: the httparchive ArchivedHttpResponse
      and returns the rule return_value of the first rule that returns
      should_stop == True, or the last rule's return_value if all rules returns
      should_stop == False.
    """
    matches = [rule for rule in self._rules if rule.IsType(rule_type_name)]
    return _Rule(matches)

  def __str__(self):
    return _ToString(self._rules)

  def __repr__(self):
    return str(self)


class _Rule(object):
  """Calls a sequence of Rule objects until one returns should_stop."""

  def __init__(self, rules):
    self._rules = rules

  def __call__(self, request, response):
    """Calls the rules until one returns should_stop.

    Args:
      request: the httparchive ArchivedHttpRequest.
      response: the httparchive ArchivedHttpResponse, which may be None.
    Returns:
      The rule return_value of the first rule that returns should_stop == True,
      or the last rule's return_value if all rules return should_stop == False.
    """
    return_value = None
    for rule in self._rules:
      should_stop, return_value = rule.ApplyRule(
          return_value, request, response)
      if should_stop:
        break
    return return_value

  def __str__(self):
    return _ToString(self._rules)

  def __repr__(self):
    return str(self)


def _ToString(rules):
  """Formats a sequence of Rule objects into a string."""
  return '[\n%s\n]' % '\n'.join('%s' % rule for rule in rules)


def _Load(file_obj, allowed_imports):
  """Parses and evaluates all rules in the given file.

  Args:
    file_obj: a file object.
    allowed_imports: a sequence of strings, e.g.: {'rules'}.
  Returns:
    a list of rules.
  """
  rules = []
  entries = json.load(file_obj)
  if not isinstance(entries, list):
    raise Error('Expecting a list, not %s', type(entries))
  for i, entry in enumerate(entries):
    if not isinstance(entry, dict):
      raise Error('%s: Expecting a dict, not %s', i, type(entry))
    if len(entry) != 1:
      raise Error('%s: Expecting 1 item, not %d', i, len(entry))
    name, args = next(entry.iteritems())
    if not isinstance(name, basestring):
      raise Error('%s: Expecting a string TYPE, not %s', i, type(name))
    if not re.match(r'(\w+\.)*\w+$', name):
      raise Error('%s: Expecting a classname TYPE, not %s', i, name)
    if name == 'comment':
      continue
    if not isinstance(args, dict):
      raise Error('%s: Expecting a dict ARGS, not %s', i, type(args))
    fullname = str(name)
    if '.' not in fullname:
      fullname = 'rules.%s' % fullname

    modulename, classname = fullname.rsplit('.', 1)
    if '*' not in allowed_imports and modulename not in allowed_imports:
      raise Error('%s: Package %r is not in allowed_imports', i, modulename)

    module = __import__(modulename, fromlist=[classname])
    clazz = getattr(module, classname)

    missing = {s for s in ('IsType', 'ApplyRule') if not hasattr(clazz, s)}
    if missing:
      raise Error('%s: %s lacks %s', i, clazz.__name__, ' and '.join(missing))

    rule = clazz(**args)

    rules.append(rule)
  return rules
