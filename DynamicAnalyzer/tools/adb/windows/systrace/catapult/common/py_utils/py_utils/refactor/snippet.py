# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import parser
import symbol
import sys
import token
import tokenize

from py_utils.refactor import offset_token


class Snippet(object):
  """A node in the Python parse tree.

  The Python grammar is defined at:
  https://docs.python.org/2/reference/grammar.html

  There are two types of Snippets:
    TokenSnippets are leaf nodes containing actual text.
    Symbols are internal nodes representing higher-level groupings, and are
        defined by the left-hand sides of the BNFs in the above link.
  """
  @property
  def type(self):
    raise NotImplementedError()

  @property
  def type_name(self):
    raise NotImplementedError()

  @property
  def children(self):
    """Return a list of this node's children."""
    raise NotImplementedError()

  @property
  def tokens(self):
    """Return a tuple of the tokens this Snippet contains."""
    raise NotImplementedError()

  def PrintTree(self, indent=0, stream=sys.stdout):
    """Spew a pretty-printed parse tree. Mostly useful for debugging."""
    raise NotImplementedError()

  def __str__(self):
    return offset_token.Untokenize(self.tokens)

  def FindAll(self, snippet_type):
    if isinstance(snippet_type, int):
      if self.type == snippet_type:
        yield self
    else:
      if isinstance(self, snippet_type):
        yield self

    for child in self.children:
      for snippet in child.FindAll(snippet_type):
        yield snippet

  def FindChild(self, snippet_type, **kwargs):
    for child in self.children:
      if isinstance(snippet_type, int):
        if child.type != snippet_type:
          continue
      else:
        if not isinstance(child, snippet_type):
          continue

      for attribute, value in kwargs:
        if getattr(child, attribute) != value:
          break
      else:
        return child
    raise ValueError('%s is not in %s. Children are: %s' %
                     (snippet_type, self, self.children))

  def FindChildren(self, snippet_type):
    if isinstance(snippet_type, int):
      for child in self.children:
        if child.type == snippet_type:
          yield child
    else:
      for child in self.children:
        if isinstance(child, snippet_type):
          yield child


class TokenSnippet(Snippet):
  """A Snippet containing a list of tokens.

  A list of tokens may start with any number of comments and non-terminating
  newlines, but must end with a syntactically meaningful token.
  """

  def __init__(self, token_type, tokens):
    # For operators and delimiters, the TokenSnippet's type may be more specific
    # than the type of the constituent token. E.g. the TokenSnippet type is
    # token.DOT, but the token type is token.OP. This is because the parser
    # has more context than the tokenizer.
    self._type = token_type
    self._tokens = tokens
    self._modified = False

  @classmethod
  def Create(cls, token_type, string, offset=(0, 0)):
    return cls(token_type,
               [offset_token.OffsetToken(token_type, string, offset)])

  @property
  def type(self):
    return self._type

  @property
  def type_name(self):
    return token.tok_name[self.type]

  @property
  def value(self):
    return self._tokens[-1].string

  @value.setter
  def value(self, value):
    self._tokens[-1].string = value
    self._modified = True

  @property
  def children(self):
    return []

  @property
  def tokens(self):
    return tuple(self._tokens)

  @property
  def modified(self):
    return self._modified

  def PrintTree(self, indent=0, stream=sys.stdout):
    stream.write(' ' * indent)
    if not self.tokens:
      print >> stream, self.type_name
      return

    print >> stream, '%-4s' % self.type_name, repr(self.tokens[0].string)
    for tok in self.tokens[1:]:
      stream.write(' ' * indent)
      print >> stream, ' ' * max(len(self.type_name), 4), repr(tok.string)


class Symbol(Snippet):
  """A Snippet containing sub-Snippets.

  The possible types and type_names are defined in Python's symbol module."""

  def __init__(self, symbol_type, children):
    self._type = symbol_type
    self._children = children

  @property
  def type(self):
    return self._type

  @property
  def type_name(self):
    return symbol.sym_name[self.type]

  @property
  def children(self):
    return self._children

  @children.setter
  def children(self, value):  # pylint: disable=arguments-differ
    self._children = value

  @property
  def tokens(self):
    tokens = []
    for child in self.children:
      tokens += child.tokens
    return tuple(tokens)

  @property
  def modified(self):
    return any(child.modified for child in self.children)

  def PrintTree(self, indent=0, stream=sys.stdout):
    stream.write(' ' * indent)

    # If there's only one child, collapse it onto the same line.
    node = self
    while len(node.children) == 1 and len(node.children[0].children) == 1:
      print >> stream, node.type_name,
      node = node.children[0]

    print >> stream, node.type_name
    for child in node.children:
      child.PrintTree(indent + 2, stream)


def Snippetize(f):
  """Return the syntax tree of the given file."""
  f.seek(0)
  syntax_tree = parser.st2list(parser.suite(f.read()))
  tokens = offset_token.Tokenize(f)

  snippet = _SnippetizeNode(syntax_tree, tokens)
  assert not tokens
  return snippet


def _SnippetizeNode(node, tokens):
  # The parser module gives a syntax tree that discards comments,
  # non-terminating newlines, and whitespace information. Use the tokens given
  # by the tokenize module to annotate the syntax tree with the information
  # needed to exactly reproduce the original source code.
  node_type = node[0]

  if node_type >= token.NT_OFFSET:
    # Symbol.
    children = tuple(_SnippetizeNode(child, tokens) for child in node[1:])
    return Symbol(node_type, children)
  else:
    # Token.
    grabbed_tokens = []
    while tokens and (
        tokens[0].type == tokenize.COMMENT or tokens[0].type == tokenize.NL):
      grabbed_tokens.append(tokens.popleft())

    # parser has 2 NEWLINEs right before the end.
    # tokenize has 0 or 1 depending on if the file has one.
    # Create extra nodes without consuming tokens to account for this.
    if node_type == token.NEWLINE:
      for tok in tokens:
        if tok.type == token.ENDMARKER:
          return TokenSnippet(node_type, grabbed_tokens)
        if tok.type != token.DEDENT:
          break

    assert tokens[0].type == token.OP or node_type == tokens[0].type

    grabbed_tokens.append(tokens.popleft())
    return TokenSnippet(node_type, grabbed_tokens)
