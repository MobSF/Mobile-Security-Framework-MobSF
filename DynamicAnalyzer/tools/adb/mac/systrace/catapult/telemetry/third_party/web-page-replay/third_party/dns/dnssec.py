# Copyright (C) 2003-2007, 2009 Nominum, Inc.
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

"""Common DNSSEC-related functions and constants."""

RSAMD5 = 1
DH = 2
DSA = 3
ECC = 4
RSASHA1 = 5
DSANSEC3SHA1 = 6
RSASHA1NSEC3SHA1 = 7
RSASHA256 = 8
RSASHA512 = 10
INDIRECT = 252
PRIVATEDNS = 253
PRIVATEOID = 254

_algorithm_by_text = {
    'RSAMD5' : RSAMD5,
    'DH' : DH,
    'DSA' : DSA,
    'ECC' : ECC,
    'RSASHA1' : RSASHA1,
    'DSANSEC3SHA1' : DSANSEC3SHA1,
    'RSASHA1NSEC3SHA1' : RSASHA1NSEC3SHA1,
    'RSASHA256' : RSASHA256,
    'RSASHA512' : RSASHA512,
    'INDIRECT' : INDIRECT,
    'PRIVATEDNS' : PRIVATEDNS,
    'PRIVATEOID' : PRIVATEOID,
    }

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_algorithm_by_value = dict([(y, x) for x, y in _algorithm_by_text.iteritems()])

class UnknownAlgorithm(Exception):
    """Raised if an algorithm is unknown."""
    pass

def algorithm_from_text(text):
    """Convert text into a DNSSEC algorithm value
    @rtype: int"""
    
    value = _algorithm_by_text.get(text.upper())
    if value is None:
        value = int(text)
    return value

def algorithm_to_text(value):
    """Convert a DNSSEC algorithm value to text
    @rtype: string"""
    
    text = _algorithm_by_value.get(value)
    if text is None:
        text = str(value)
    return text
