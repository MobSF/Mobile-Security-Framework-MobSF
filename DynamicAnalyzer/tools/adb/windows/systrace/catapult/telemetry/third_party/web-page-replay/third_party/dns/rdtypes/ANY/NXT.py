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

import dns.exception
import dns.rdata
import dns.rdatatype
import dns.name

class NXT(dns.rdata.Rdata):
    """NXT record

    @ivar next: the next name
    @type next: dns.name.Name object
    @ivar bitmap: the type bitmap
    @type bitmap: string
    @see: RFC 2535"""

    __slots__ = ['next', 'bitmap']

    def __init__(self, rdclass, rdtype, next, bitmap):
        super(NXT, self).__init__(rdclass, rdtype)
        self.next = next
        self.bitmap = bitmap

    def to_text(self, origin=None, relativize=True, **kw):
        next = self.next.choose_relativity(origin, relativize)
        bits = []
        for i in xrange(0, len(self.bitmap)):
            byte = ord(self.bitmap[i])
            for j in xrange(0, 8):
                if byte & (0x80 >> j):
                    bits.append(dns.rdatatype.to_text(i * 8 + j))
        text = ' '.join(bits)
        return '%s %s' % (next, text)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        next = tok.get_name()
        next = next.choose_relativity(origin, relativize)
        bitmap = ['\x00', '\x00', '\x00', '\x00',
                  '\x00', '\x00', '\x00', '\x00',
                  '\x00', '\x00', '\x00', '\x00',
                  '\x00', '\x00', '\x00', '\x00' ]
        while 1:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                break
            if token.value.isdigit():
                nrdtype = int(token.value)
            else:
                nrdtype = dns.rdatatype.from_text(token.value)
            if nrdtype == 0:
                raise dns.exception.SyntaxError("NXT with bit 0")
            if nrdtype > 127:
                raise dns.exception.SyntaxError("NXT with bit > 127")
            i = nrdtype // 8
            bitmap[i] = chr(ord(bitmap[i]) | (0x80 >> (nrdtype % 8)))
        bitmap = dns.rdata._truncate_bitmap(bitmap)
        return cls(rdclass, rdtype, next, bitmap)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        self.next.to_wire(file, None, origin)
        file.write(self.bitmap)

    def to_digestable(self, origin = None):
        return self.next.to_digestable(origin) + self.bitmap

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (next, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        bitmap = wire[current : current + rdlen]
        if not origin is None:
            next = next.relativize(origin)
        return cls(rdclass, rdtype, next, bitmap)

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        self.next = self.next.choose_relativity(origin, relativize)

    def _cmp(self, other):
        v = cmp(self.next, other.next)
        if v == 0:
            v = cmp(self.bitmap, other.bitmap)
        return v
