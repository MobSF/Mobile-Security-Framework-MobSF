# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Unfortunately, there's no easy way to decode Modified UTF8 in Python, so we
# have to write a custom decoder. This one is error tolerant and will decode
# anything resembling mutf8.

def _decode(b):
    # decode arbitrary utf8 codepoints, tolerating surrogate pairs, nonstandard encodings, etc.
    for x in b:
        if x < 128:
            yield x
        else:
            # figure out how many bytes
            extra = 0
            for i in range(6, 0, -1):
                if x & (1<<i):
                    extra += 1
                else:
                    break

            bits = x % (1 << 6-extra)
            for _ in range(extra):
                bits = (bits << 6) ^ (next(b) & 63)
            yield bits

def _fixPairs(codes):
    # convert surrogate pairs to single code points
    for x in codes:
        if 0xD800 <= x < 0xDC00:
            high = x - 0xD800
            low = next(codes) - 0xDC00
            yield 0x10000 + (high << 10) + (low & 1023)
        else:
            yield x

def decode(b):
    try:
        return b.decode('utf8')
    except UnicodeDecodeError:
        return ''.join(map(chr, _fixPairs(_decode(iter(b)))))
