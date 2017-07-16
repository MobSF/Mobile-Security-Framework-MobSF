# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_utils.refactor import snippet


class AnnotatedSymbol(snippet.Symbol):
  def __init__(self, symbol_type, children):
    super(AnnotatedSymbol, self).__init__(symbol_type, children)
    self._modified = False

  @property
  def modified(self):
    if self._modified:
      return True
    return super(AnnotatedSymbol, self).modified

  def __setattr__(self, name, value):
    if (hasattr(self.__class__, name) and
        isinstance(getattr(self.__class__, name), property)):
      self._modified = True
    return super(AnnotatedSymbol, self).__setattr__(name, value)

  def Cut(self, child):
    for i in xrange(len(self._children)):
      if self._children[i] == child:
        self._modified = True
        del self._children[i]
        break
    else:
      raise ValueError('%s is not in %s.' % (child, self))

  def Paste(self, child):
    self._modified = True
    self._children.append(child)
