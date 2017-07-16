# Copyright (C) 2003-2007, 2009, 2010 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""IPv4 helper functions."""

import socket
import sys

if sys.hexversion < 0x02030000 or sys.platform == 'win32':
    #
    # Some versions of Python 2.2 have an inet_aton which rejects
    # the valid IP address '255.255.255.255'.  It appears this
    # problem is still present on the Win32 platform even in 2.3.
    # We'll work around the problem.
    #
    def inet_aton(text):
        if text == '255.255.255.255':
            return '\xff' * 4
        else:
            return socket.inet_aton(text)
else:
    inet_aton = socket.inet_aton

inet_ntoa = socket.inet_ntoa
