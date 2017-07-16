# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import symbol

from py_utils.refactor.annotated_symbol import base_symbol


__all__ = [
    'Function',
]


class Function(base_symbol.AnnotatedSymbol):
  # pylint: disable=abstract-class-not-used

  @classmethod
  def Annotate(cls, symbol_type, children):
    if symbol_type != symbol.stmt:
      return None

    compound_statement = children[0]
    if compound_statement.type != symbol.compound_stmt:
      return None

    statement = compound_statement.children[0]
    if statement.type == symbol.funcdef:
      return cls(statement.type, statement.children)
    elif (statement.type == symbol.decorated and
          statement.children[-1].type == symbol.funcdef):
      return cls(statement.type, statement.children)
    else:
      return None

  @property
  def suite(self):
    # TODO: Complete.
    raise NotImplementedError()

  def FindChild(self, snippet_type, **kwargs):
    return self.suite.FindChild(snippet_type, **kwargs)

  def FindChildren(self, snippet_type):
    return self.suite.FindChildren(snippet_type)

  def Cut(self, child):
    self.suite.Cut(child)

  def Paste(self, child):
    self.suite.Paste(child)
