# This code is original from jsmin by Douglas Crockford, it was translated to
# Python by Baruch Even. It was rewritten by Dave St.Germain for speed.
#
# The MIT License (MIT)
# 
# Copyright (c) 2013 Dave St.Germain
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import sys
is_3 = sys.version_info >= (3, 0)
if is_3:
    import io
else:
    import StringIO
    try:
        import cStringIO
    except ImportError:
        cStringIO = None


__all__ = ['jsmin', 'JavascriptMinify']
__version__ = '2.2.1'


def jsmin(js, **kwargs):
    """
    returns a minified version of the javascript string
    """
    if not is_3:        
        if cStringIO and not isinstance(js, unicode):
            # strings can use cStringIO for a 3x performance
            # improvement, but unicode (in python2) cannot
            klass = cStringIO.StringIO
        else:
            klass = StringIO.StringIO
    else:
        klass = io.StringIO
    ins = klass(js)
    outs = klass()
    JavascriptMinify(ins, outs, **kwargs).minify()
    return outs.getvalue()


class JavascriptMinify(object):
    """
    Minify an input stream of javascript, writing
    to an output stream
    """

    def __init__(self, instream=None, outstream=None, quote_chars="'\""):
        self.ins = instream
        self.outs = outstream
        self.quote_chars = quote_chars

    def minify(self, instream=None, outstream=None):
        if instream and outstream:
            self.ins, self.outs = instream, outstream
        
        self.is_return = False
        self.return_buf = ''
        
        def write(char):
            # all of this is to support literal regular expressions.
            # sigh
            if char in 'return':
                self.return_buf += char
                self.is_return = self.return_buf == 'return'
            else:
                self.return_buf = ''
                self.is_return = self.is_return and char < '!'
            self.outs.write(char)
            if self.is_return:
                self.return_buf = ''

        read = self.ins.read

        space_strings = "abcdefghijklmnopqrstuvwxyz"\
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$\\"
        self.space_strings = space_strings
        starters, enders = '{[(+-', '}])+-/' + self.quote_chars
        newlinestart_strings = starters + space_strings + self.quote_chars
        newlineend_strings = enders + space_strings + self.quote_chars
        self.newlinestart_strings = newlinestart_strings
        self.newlineend_strings = newlineend_strings

        do_newline = False
        do_space = False
        escape_slash_count = 0
        in_quote = ''
        quote_buf = []

        previous = ';'
        previous_non_space = ';'
        next1 = read(1)

        while next1:
            next2 = read(1)
            if in_quote:
                quote_buf.append(next1)

                if next1 == in_quote:
                    numslashes = 0
                    for c in reversed(quote_buf[:-1]):
                        if c != '\\':
                            break
                        else:
                            numslashes += 1
                    if numslashes % 2 == 0:
                        in_quote = ''
                        write(''.join(quote_buf))
            elif next1 in '\r\n':
                next2, do_newline = self.newline(
                    previous_non_space, next2, do_newline)
            elif next1 < '!':
                if (previous_non_space in space_strings \
                    or previous_non_space > '~') \
                    and (next2 in space_strings or next2 > '~'):
                    do_space = True
                elif previous_non_space in '-+' and next2 == previous_non_space:
                    # protect against + ++ or - -- sequences
                    do_space = True
                elif self.is_return and next2 == '/':
                    # returning a regex...
                    write(' ')
            elif next1 == '/':
                if do_space:
                    write(' ')
                if next2 == '/':
                    # Line comment: treat it as a newline, but skip it
                    next2 = self.line_comment(next1, next2)
                    next1 = '\n'
                    next2, do_newline = self.newline(
                        previous_non_space, next2, do_newline)
                elif next2 == '*':
                    self.block_comment(next1, next2)
                    next2 = read(1)
                    if previous_non_space in space_strings:
                        do_space = True
                    next1 = previous
                else:
                    if previous_non_space in '{(,=:[?!&|;' or self.is_return:
                        self.regex_literal(next1, next2)
                        # hackish: after regex literal next1 is still /
                        # (it was the initial /, now it's the last /)
                        next2 = read(1)
                    else:
                        write('/')
            else:
                if do_newline:
                    write('\n')
                    do_newline = False
                    do_space = False
                if do_space:
                    do_space = False
                    write(' ')

                write(next1)
                if next1 in self.quote_chars:
                    in_quote = next1
                    quote_buf = []

            if next1 >= '!':
                previous_non_space = next1

            if next1 == '\\':
                escape_slash_count += 1
            else:
                escape_slash_count = 0

            previous = next1
            next1 = next2

    def regex_literal(self, next1, next2):
        assert next1 == '/'  # otherwise we should not be called!

        self.return_buf = ''

        read = self.ins.read
        write = self.outs.write

        in_char_class = False

        write('/')

        next = next2
        while next and (next != '/' or in_char_class):
            write(next)
            if next == '\\':
                write(read(1))  # whatever is next is escaped
            elif next == '[':
                write(read(1))  # character class cannot be empty
                in_char_class = True
            elif next == ']':
                in_char_class = False
            next = read(1)

        write('/')

    def line_comment(self, next1, next2):
        assert next1 == next2 == '/'

        read = self.ins.read

        while next1 and next1 not in '\r\n':
            next1 = read(1)
        while next1 and next1 in '\r\n':
            next1 = read(1)

        return next1

    def block_comment(self, next1, next2):
        assert next1 == '/'
        assert next2 == '*'

        read = self.ins.read

        # Skip past first /* and avoid catching on /*/...*/
        next1 = read(1)
        next2 = read(1)

        comment_buffer = '/*'
        while next1 != '*' or next2 != '/':
            comment_buffer += next1
            next1 = next2
            next2 = read(1)

        if comment_buffer.startswith("/*!"):
            # comment needs preserving
            self.outs.write(comment_buffer)
            self.outs.write("*/\n")


    def newline(self, previous_non_space, next2, do_newline):
        read = self.ins.read

        if previous_non_space and (
                        previous_non_space in self.newlineend_strings
                        or previous_non_space > '~'):
            while 1:
                if next2 < '!':
                    next2 = read(1)
                    if not next2:
                        break
                else:
                    if next2 in self.newlinestart_strings \
                            or next2 > '~' or next2 == '/':
                        do_newline = True
                    break

        return next2, do_newline
