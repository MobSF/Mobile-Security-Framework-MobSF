#! /usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import imp
import os
import re
import sys
import textwrap
import types

# A markdown code block template: https://goo.gl/9EsyRi
_CODE_BLOCK_FORMAT = '''```{language}
{code}
```
'''

_DEVIL_ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..'))


def md_bold(raw_text):
  """Returns markdown-formatted bold text."""
  return '**%s**' % md_escape(raw_text, characters='*')


def md_code(raw_text, language):
  """Returns a markdown-formatted code block in the given language."""
  return _CODE_BLOCK_FORMAT.format(
      language=language or '',
      code=md_escape(raw_text, characters='`'))


def md_escape(raw_text, characters='*_'):
  """Escapes * and _."""
  def escape_char(m):
    return '\\%s' % m.group(0)
  pattern = '[%s]' % re.escape(characters)
  return re.sub(pattern, escape_char, raw_text)


def md_heading(raw_text, level):
  """Returns markdown-formatted heading."""
  adjusted_level = min(max(level, 0), 6)
  return '%s%s%s' % (
      '#' * adjusted_level, ' ' if adjusted_level > 0 else '', raw_text)


def md_inline_code(raw_text):
  """Returns markdown-formatted inline code."""
  return '`%s`' % md_escape(raw_text, characters='`')


def md_italic(raw_text):
  """Returns markdown-formatted italic text."""
  return '*%s*' % md_escape(raw_text, characters='*')


def md_link(link_text, link_target):
  """returns a markdown-formatted link."""
  return '[%s](%s)' % (
      md_escape(link_text, characters=']'),
      md_escape(link_target, characters=')'))


class MarkdownHelpFormatter(argparse.HelpFormatter):
  """A really bare-bones argparse help formatter that generates valid markdown.

  This will generate something like:

  usage

  # **section heading**:

  ## **--argument-one**

  ```
  argument-one help text
  ```

  """

  #override
  def _format_usage(self, usage, actions, groups, prefix):
    usage_text = super(MarkdownHelpFormatter, self)._format_usage(
        usage, actions, groups, prefix)
    return md_code(usage_text, language=None)

  #override
  def format_help(self):
    self._root_section.heading = md_heading(self._prog, level=1)
    return super(MarkdownHelpFormatter, self).format_help()

  #override
  def start_section(self, heading):
    super(MarkdownHelpFormatter, self).start_section(
        md_heading(heading, level=2))

  #override
  def _format_action(self, action):
    lines = []
    action_header = self._format_action_invocation(action)
    lines.append(md_heading(action_header, level=3))
    if action.help:
      lines.append(md_code(self._expand_help(action), language=None))
    lines.extend(['', ''])
    return '\n'.join(lines)


class MarkdownHelpAction(argparse.Action):
  def __init__(self, option_strings,
               dest=argparse.SUPPRESS, default=argparse.SUPPRESS,
               **kwargs):
    super(MarkdownHelpAction, self).__init__(
        option_strings=option_strings,
        dest=dest,
        default=default,
        nargs=0,
        **kwargs)

  def __call__(self, parser, namespace, values, option_string=None):
    parser.formatter_class = MarkdownHelpFormatter
    parser.print_help()
    parser.exit()


def add_md_help_argument(parser):
  """Adds --md-help to the given argparse.ArgumentParser.

  Running a script with --md-help will print the help text for that script
  as valid markdown.

  Args:
    parser: The ArgumentParser to which --md-help should be added.
  """
  parser.add_argument('--md-help', action=MarkdownHelpAction,
                      help='print Markdown-formatted help text and exit.')


def load_module_from_path(module_path):
  """Load a module given only the path name.

  Also loads package modules as necessary.

  Args:
    module_path: An absolute path to a python module.
  Returns:
    The module object for the given path.
  """
  module_names = [os.path.splitext(os.path.basename(module_path))[0]]
  d = os.path.dirname(module_path)

  while os.path.exists(os.path.join(d, '__init__.py')):
    module_names.append(os.path.basename(d))
    d = os.path.dirname(d)

  d = [d]

  module = None
  full_module_name = ''
  for package_name in reversed(module_names):
    if module:
      d = module.__path__
      full_module_name += '.'
    r = imp.find_module(package_name, d)
    full_module_name += package_name
    module = imp.load_module(full_module_name, *r)
  return module


def md_module(module_obj, module_path=None, module_link=None):
  """Write markdown documentation for a class.

  Documents public classes and functions.

  Args:
    class_obj: a types.TypeType object for the class that should be
      documented.
  Returns:
    A list of markdown-formatted lines.
  """
  def should_doc(name):
    return (type(module_obj.__dict__[name]) != types.ModuleType
            and not name.startswith('_'))

  stuff_to_doc = sorted(
    obj for name, obj in module_obj.__dict__.iteritems()
    if should_doc(name))

  classes_to_doc = []
  functions_to_doc = []

  for s in stuff_to_doc:
    if type(s) == types.TypeType:
      classes_to_doc.append(s)
    elif type(s) == types.FunctionType:
      functions_to_doc.append(s)

  command = ['devil/utils/markdown.py']
  if module_link:
    command.extend(['--module-link', module_link])
  if module_path:
    command.append(os.path.relpath(module_path, _DEVIL_ROOT))

  heading_text = module_obj.__name__
  if module_link:
    heading_text = md_link(heading_text, module_link)

  content = [
      md_heading(heading_text, level=1),
      '',
      md_italic('This page was autogenerated by %s'
          % md_inline_code(' '.join(command))),
      '',
  ]

  for c in classes_to_doc:
    content += md_class(c)
  for f in functions_to_doc:
    content += md_function(f)

  print '\n'.join(content)

  return 0


def md_class(class_obj):
  """Write markdown documentation for a class.

  Documents public methods. Does not currently document subclasses.

  Args:
    class_obj: a types.TypeType object for the class that should be
      documented.
  Returns:
    A list of markdown-formatted lines.
  """
  content = [md_heading(md_escape(class_obj.__name__), level=2)]
  content.append('')
  if class_obj.__doc__:
    content.extend(md_docstring(class_obj.__doc__))

  def should_doc(name, obj):
    return (type(obj) == types.FunctionType
            and (name.startswith('__') or not name.startswith('_')))

  methods_to_doc = sorted(
      obj for name, obj in class_obj.__dict__.iteritems()
      if should_doc(name, obj))

  for m in methods_to_doc:
    content.extend(md_function(m, class_obj=class_obj))

  return content


def md_docstring(docstring):
  """Write a markdown-formatted docstring.

  Returns:
    A list of markdown-formatted lines.
  """
  content = []
  lines = textwrap.dedent(docstring).splitlines()
  content.append(md_escape(lines[0]))
  lines = lines[1:]
  while lines and (not lines[0] or lines[0].isspace()):
    lines = lines[1:]

  if not all(l.isspace() for l in lines):
    content.append(md_code('\n'.join(lines), language=None))
    content.append('')
  return content


def md_function(func_obj, class_obj=None):
  """Write markdown documentation for a function.

  Args:
    func_obj: a types.FunctionType object for the function that should be
      documented.
  Returns:
    A list of markdown-formatted lines.
  """
  if class_obj:
    heading_text = '%s.%s' % (class_obj.__name__, func_obj.__name__)
  else:
    heading_text = func_obj.__name__
  content = [md_heading(md_escape(heading_text), level=3)]
  content.append('')

  if func_obj.__doc__:
    content.extend(md_docstring(func_obj.__doc__))

  return content


def main(raw_args):
  """Write markdown documentation for the module at the provided path.

  Args:
    raw_args: the raw command-line args. Usually sys.argv[1:].
  Returns:
    An integer exit code. 0 for success, non-zero for failure.
  """
  parser = argparse.ArgumentParser()
  parser.add_argument('--module-link')
  parser.add_argument('module_path', type=os.path.realpath)
  args = parser.parse_args(raw_args)

  return md_module(
      load_module_from_path(args.module_path),
      module_link=args.module_link)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))

