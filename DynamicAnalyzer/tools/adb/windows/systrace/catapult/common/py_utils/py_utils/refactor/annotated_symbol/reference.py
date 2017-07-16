# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import itertools
import symbol
import token

from py_utils.refactor.annotated_symbol import base_symbol
from py_utils.refactor import snippet


__all__ = [
    'Reference',
]


class Reference(base_symbol.AnnotatedSymbol):
  @classmethod
  def Annotate(cls, nodes):
    if not nodes:
      return None
    if nodes[0].type != symbol.atom:
      return None
    if not nodes[0].children or nodes[0].children[0].type != token.NAME:
      return None

    for i in xrange(1, len(nodes)):
      if not nodes:
        break
      if nodes[i].type != symbol.trailer:
        break
      if len(nodes[i].children) != 2:
        break
      if (nodes[i].children[0].type != token.DOT or
          nodes[i].children[1].type != token.NAME):
        break
    else:
      i = len(nodes)

    return [cls(nodes[:i])] + nodes[i:]

  def __init__(self, children):
    super(Reference, self).__init__(-1, children)

  @property
  def type_name(self):
    return 'attribute_reference'

  @property
  def value(self):
    return ''.join(token_snippet.value
                   for child in self.children
                   for token_snippet in child.children)

  @value.setter
  def value(self, value):
    value_parts = value.split('.')

    # If we have too many children, cut the list down to size.
    self._children = self._children[:len(value_parts)]

    # Update child nodes.
    for child, value_part in itertools.izip_longest(
        self._children, value_parts):
      if child:
        # Modify existing children. This helps preserve comments and spaces.
        child.children[-1].value = value_part
      else:
        # Add children as needed.
        token_snippets = [
            snippet.TokenSnippet.Create(token.DOT, '.'),
            snippet.TokenSnippet.Create(token.NAME, value_part),
        ]
        self._children.append(snippet.Symbol(symbol.trailer, token_snippets))
