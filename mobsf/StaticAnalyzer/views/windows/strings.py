# -*- coding: utf_8 -*-
"""Bounded ASCII and UTF-16LE string extraction for PE binaries."""
import re

MIN_LEN = 6
MAX_STRING_LEN = 4096
CHUNK_SIZE = 1024 * 1024
MAX_READ_BYTES = 64 * 1024 * 1024

_PATTERNS = (
    (re.compile(rb'[\x20-\x7e]{%d,}' % MIN_LEN), 'ascii'),
    (re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % MIN_LEN), 'utf-16-le'),
)
# Bytes kept from the previous chunk so strings crossing a chunk
# boundary are matched whole in the next pass.
_OVERLAP = MAX_STRING_LEN * 2


def _decode(raw, encoding):
    text = raw[:MAX_STRING_LEN * 2].decode(encoding, 'ignore')
    if text[:1].isalnum() or text[:1] in '/\\.:{':
        return text[:MAX_STRING_LEN]
    return None


def extract_strings(path, max_strings, max_bytes=MAX_READ_BYTES):
    """Return unique printable strings from the first max_bytes of path."""
    found = set()
    read = 0
    base = 0
    buf = b''
    done_until = [0] * len(_PATTERNS)
    with open(path, 'rb') as fp:
        while len(found) < max_strings:
            chunk = fp.read(min(CHUNK_SIZE, max_bytes - read))
            read += len(chunk)
            final = not chunk or read >= max_bytes
            buf += chunk
            for idx, (regex, encoding) in enumerate(_PATTERNS):
                for match in regex.finditer(buf):
                    start, end = base + match.start(), base + match.end()
                    if start < done_until[idx]:
                        continue
                    if not final and match.end() == len(buf):
                        # May continue in the next chunk
                        break
                    done_until[idx] = end
                    text = _decode(match.group(), encoding)
                    if text:
                        found.add(text)
                        if len(found) >= max_strings:
                            break
            if final:
                break
            keep = min(len(buf), _OVERLAP)
            base += len(buf) - keep
            buf = buf[-keep:] if keep else b''
    return sorted(found)
