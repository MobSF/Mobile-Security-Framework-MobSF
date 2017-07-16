# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=wildcard-import
from py_utils.refactor.annotated_symbol.class_definition import *
from py_utils.refactor.annotated_symbol.function_definition import *
from py_utils.refactor.annotated_symbol.import_statement import *
from py_utils.refactor.annotated_symbol.reference import *
from py_utils.refactor import snippet


__all__ = [
    'Annotate',

    'Class',
    'Function',
    'Import',
    'Reference',
]


# Specific symbol types with extra methods for manipulating them.
# Python's full grammar is here:
# https://docs.python.org/2/reference/grammar.html

# Annotated Symbols have an Annotate classmethod that takes a symbol type and
# list of children, and returns an instance of that annotated Symbol.

ANNOTATED_SYMBOLS = (
    AsName,
    Class,
    DottedName,
    ImportFrom,
    ImportName,
    Function,
)


# Unfortunately, some logical groupings are not represented by a node in the
# parse tree. To work around this, some annotated Symbols have an Annotate
# classmethod that takes and returns a list of Snippets instead.

ANNOTATED_GROUPINGS = (
    Reference,
)


def Annotate(f):
  """Return the syntax tree of the given file."""
  return _AnnotateNode(snippet.Snippetize(f))


def _AnnotateNode(node):
  if not isinstance(node, snippet.Symbol):
    return node

  children = map(_AnnotateNode, node.children)

  for symbol_type in ANNOTATED_GROUPINGS:
    annotated_grouping = symbol_type.Annotate(children)
    if annotated_grouping:
      children = annotated_grouping
      break

  for symbol_type in ANNOTATED_SYMBOLS:
    annotated_symbol = symbol_type.Annotate(node.type, children)
    if annotated_symbol:
      return annotated_symbol

  return snippet.Symbol(node.type, children)
