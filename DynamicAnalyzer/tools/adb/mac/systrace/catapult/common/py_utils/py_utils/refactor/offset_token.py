# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import itertools
import token
import tokenize


def _Pairwise(iterable):
  """s -> (None, s0), (s0, s1), (s1, s2), (s2, s3), ..."""
  a, b = itertools.tee(iterable)
  a = itertools.chain((None,), a)
  return itertools.izip(a, b)


class OffsetToken(object):
  """A Python token with a relative position.

  A token is represented by a type defined in Python's token module, a string
  representing the content, and an offset. Using relative positions makes it
  easy to insert and remove tokens.
  """

  def __init__(self, token_type, string, offset):
    self._type = token_type
    self._string = string
    self._offset = offset

  @property
  def type(self):
    return self._type

  @property
  def type_name(self):
    return token.tok_name[self._type]

  @property
  def string(self):
    return self._string

  @string.setter
  def string(self, value):
    self._string = value

  @property
  def offset(self):
    return self._offset

  def __str__(self):
    return str((self.type_name, self.string, self.offset))


def Tokenize(f):
  """Read tokens from a file-like object.

  Args:
    f: Any object that has a readline method.

  Returns:
    A collections.deque containing OffsetTokens. Deques are cheaper and easier
    to manipulate sequentially than lists.
  """
  f.seek(0)
  tokenize_tokens = tokenize.generate_tokens(f.readline)

  offset_tokens = collections.deque()
  for prev_token, next_token in _Pairwise(tokenize_tokens):
    token_type, string, (srow, scol), _, _ = next_token
    if not prev_token:
      offset_tokens.append(OffsetToken(token_type, string, (0, 0)))
    else:
      erow, ecol = prev_token[3]
      if erow == srow:
        offset_tokens.append(OffsetToken(token_type, string, (0, scol - ecol)))
      else:
        offset_tokens.append(OffsetToken(
            token_type, string, (srow - erow, scol)))

  return offset_tokens


def Untokenize(offset_tokens):
  """Return the string representation of an iterable of OffsetTokens."""
  # Make a copy. Don't modify the original.
  offset_tokens = collections.deque(offset_tokens)

  # Strip leading NL tokens.
  while offset_tokens[0].type == tokenize.NL:
    offset_tokens.popleft()

  # Strip leading vertical whitespace.
  first_token = offset_tokens.popleft()
  # Take care not to modify the existing token. Create a new one in its place.
  first_token = OffsetToken(first_token.type, first_token.string,
                            (0, first_token.offset[1]))
  offset_tokens.appendleft(first_token)

  # Convert OffsetTokens to tokenize tokens.
  tokenize_tokens = []
  row = 1
  col = 0
  for t in offset_tokens:
    offset_row, offset_col = t.offset
    if offset_row == 0:
      col += offset_col
    else:
      row += offset_row
      col = offset_col
    tokenize_tokens.append((t.type, t.string, (row, col), (row, col), None))

  # tokenize can't handle whitespace before line continuations.
  # So add a space.
  return tokenize.untokenize(tokenize_tokens).replace('\\\n', ' \\\n')
