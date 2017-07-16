# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import itertools
import keyword
import symbol
import token

from py_utils.refactor.annotated_symbol import base_symbol
from py_utils.refactor import snippet


__all__ = [
    'AsName',
    'DottedName',
    'Import',
    'ImportFrom',
    'ImportName',
]


class DottedName(base_symbol.AnnotatedSymbol):
  @classmethod
  def Annotate(cls, symbol_type, children):
    if symbol_type != symbol.dotted_name:
      return None
    return cls(symbol_type, children)

  @property
  def value(self):
    return ''.join(token_snippet.value for token_snippet in self._children)

  @value.setter
  def value(self, value):
    value_parts = value.split('.')
    for value_part in value_parts:
      if keyword.iskeyword(value_part):
        raise ValueError('%s is a reserved keyword.' % value_part)

    # If we have too many children, cut the list down to size.
    self._children = self._children[:len(value_parts)*2-1]

    # Update child nodes.
    for child, value_part in itertools.izip_longest(
        self._children[::2], value_parts):
      if child:
        # Modify existing children. This helps preserve comments and spaces.
        child.value = value_part
      else:
        # Add children as needed.
        self._children.append(snippet.TokenSnippet.Create(token.DOT, '.'))
        self._children.append(
            snippet.TokenSnippet.Create(token.NAME, value_part))


class AsName(base_symbol.AnnotatedSymbol):
  @classmethod
  def Annotate(cls, symbol_type, children):
    if (symbol_type != symbol.dotted_as_name and
        symbol_type != symbol.import_as_name):
      return None
    return cls(symbol_type, children)

  @property
  def name(self):
    return self.children[0].value

  @name.setter
  def name(self, value):
    self.children[0].value = value

  @property
  def alias(self):
    if len(self.children) < 3:
      return None
    return self.children[2].value

  @alias.setter
  def alias(self, value):
    if keyword.iskeyword(value):
      raise ValueError('%s is a reserved keyword.' % value)

    if value:
      if len(self.children) < 3:
        # If we currently have no alias, add one.
        self.children.append(
            snippet.TokenSnippet.Create(token.NAME, 'as', (0, 1)))
        self.children.append(
            snippet.TokenSnippet.Create(token.NAME, value, (0, 1)))
      else:
        # We already have an alias. Just update the value.
        self.children[2].value = value
    else:
      # Removing the alias. Strip the "as foo".
      self.children = [self.children[0]]


class Import(base_symbol.AnnotatedSymbol):
  """An import statement.

  Example:
    import a.b.c as d
    from a.b import c as d

  In these examples,
    path == 'a.b.c'
    alias == 'd'
    root == 'a.b' (only for "from" imports)
    module == 'c' (only for "from" imports)
    name (read-only) == the name used by references to the module, which is the
    alias if there is one, the full module path in "full" imports, and the
    module name in "from" imports.
  """
  @property
  def has_from(self):
    """Returns True iff the import statment is of the form "from x import y"."""
    raise NotImplementedError()

  @property
  def values(self):
    raise NotImplementedError()

  @property
  def paths(self):
    raise NotImplementedError()

  @property
  def aliases(self):
    raise NotImplementedError()

  @property
  def path(self):
    """The full dotted path of the module."""
    raise NotImplementedError()

  @path.setter
  def path(self, value):
    raise NotImplementedError()

  @property
  def alias(self):
    """The alias, if the module is renamed with "as". None otherwise."""
    raise NotImplementedError()

  @alias.setter
  def alias(self, value):
    raise NotImplementedError()

  @property
  def name(self):
    """The name used to reference this import's module."""
    raise NotImplementedError()


class ImportName(Import):
  @classmethod
  def Annotate(cls, symbol_type, children):
    if symbol_type != symbol.import_stmt:
      return None
    if children[0].type != symbol.import_name:
      return None
    assert len(children) == 1
    return cls(symbol_type, children[0].children)

  @property
  def has_from(self):
    return False

  @property
  def values(self):
    dotted_as_names = self.children[1]
    return tuple((dotted_as_name.name, dotted_as_name.alias)
                 for dotted_as_name in dotted_as_names.children[::2])

  @property
  def paths(self):
    return tuple(path for path, _ in self.values)

  @property
  def aliases(self):
    return tuple(alias for _, alias in self.values)

  @property
  def _dotted_as_name(self):
    dotted_as_names = self.children[1]
    if len(dotted_as_names.children) != 1:
      raise NotImplementedError(
          'This method only works if the statement has one import.')
    return dotted_as_names.children[0]

  @property
  def path(self):
    return self._dotted_as_name.name

  @path.setter
  def path(self, value):  # pylint: disable=arguments-differ
    self._dotted_as_name.name = value

  @property
  def alias(self):
    return self._dotted_as_name.alias

  @alias.setter
  def alias(self, value):  # pylint: disable=arguments-differ
    self._dotted_as_name.alias = value

  @property
  def name(self):
    if self.alias:
      return self.alias
    else:
      return self.path


class ImportFrom(Import):
  @classmethod
  def Annotate(cls, symbol_type, children):
    if symbol_type != symbol.import_stmt:
      return None
    if children[0].type != symbol.import_from:
      return None
    assert len(children) == 1
    return cls(symbol_type, children[0].children)

  @property
  def has_from(self):
    return True

  @property
  def values(self):
    try:
      import_as_names = self.FindChild(symbol.import_as_names)
    except ValueError:
      return (('*', None),)

    return tuple((import_as_name.name, import_as_name.alias)
                 for import_as_name in import_as_names.children[::2])

  @property
  def paths(self):
    module = self.module
    return tuple('.'.join((module, name)) for name, _ in self.values)

  @property
  def aliases(self):
    return tuple(alias for _, alias in self.values)

  @property
  def root(self):
    return self.FindChild(symbol.dotted_name).value

  @root.setter
  def root(self, value):
    self.FindChild(symbol.dotted_name).value = value

  @property
  def _import_as_name(self):
    try:
      import_as_names = self.FindChild(symbol.import_as_names)
    except ValueError:
      return None

    if len(import_as_names.children) != 1:
      raise NotImplementedError(
          'This method only works if the statement has one import.')

    return import_as_names.children[0]

  @property
  def module(self):
    import_as_name = self._import_as_name
    if import_as_name:
      return import_as_name.name
    else:
      return '*'

  @module.setter
  def module(self, value):
    if keyword.iskeyword(value):
      raise ValueError('%s is a reserved keyword.' % value)

    import_as_name = self._import_as_name
    if value == '*':
      # TODO: Implement this.
      raise NotImplementedError()
    else:
      if import_as_name:
        import_as_name.name = value
      else:
        # TODO: Implement this.
        raise NotImplementedError()

  @property
  def path(self):
    return '.'.join((self.root, self.module))

  @path.setter
  def path(self, value):  # pylint: disable=arguments-differ
    self.root, _, self.module = value.rpartition('.')

  @property
  def alias(self):
    import_as_name = self._import_as_name
    if import_as_name:
      return import_as_name.alias
    else:
      return None

  @alias.setter
  def alias(self, value):  # pylint: disable=arguments-differ
    import_as_name = self._import_as_name
    if not import_as_name:
      raise NotImplementedError('Cannot change alias for "import *".')
    import_as_name.alias = value

  @property
  def name(self):
    if self.alias:
      return self.alias
    else:
      return self.module
