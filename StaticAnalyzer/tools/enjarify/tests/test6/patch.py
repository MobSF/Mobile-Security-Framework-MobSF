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
import zipfile, os, sys
import zlib, hashlib, struct
import random

ordsets = [
	list(range(65, 91)) + list(range(97, 123)) + list(range(48, 58)) + [36, 45, 95],
	range(0xa1, 0x1fff+1),
	range(0x2010, 0x2027+1),
	range(0x2030, 0xd7ff+1),
	range(0xe000, 0xffef+1),
	range(0x10000, 0x10ffff+1),
	list(range(0x300, 0x36f+1)) + list(range(0x20D0, 0x20FF+1)) + list(range(0xFE20, 0xFE2F+1)),
]
interesting = [0xA1, 0x343, 0xFDD0, 0xFEFF, 0x1FFFE, 0x8FFFE, 0x10FFFF]

def uleb128(x):
	assert(0 <= x)
	vals = []
	while x or not vals:
		vals.append(128 | (x & 127))
		x = x >> 7
	vals[-1] &= 127
	return bytes(vals)

def toU16(codepoint):
	if codepoint < 0x10000:
		return chr(codepoint)
	codepoint -= 0x10000
	return chr(0xD800 + (codepoint >> 10)) + chr(0xDC00 + (codepoint & 1023))

def simpleGen(rand, choices):
	mandatory = [x for x in interesting if x in choices]
	while mandatory:
		x = rand.choice(mandatory)
		mandatory.remove(x)
		yield x
	while 1:
		yield rand.choice(choices)

def multiGen(rand):
	used = set()
	while 1:
		choices = rand.choice(ordsets)
		x = random.choice(choices)
		if x not in used:
			yield x
		used.add(x)

def genUnicode(gen, prefix, suffix, size):
	asize = size - 1 - len(suffix)
	nwords = len(prefix) + len(suffix)
	data = prefix

	while len(uleb128(nwords)) + len(data) < asize:
		c = toU16(next(gen))
		d = c.encode('utf8', errors='surrogatepass')
		if len(uleb128(nwords+len(c))) + len(data) + len(d) > asize:
			break
		nwords += len(c)
		data += d

	while len(uleb128(nwords)) + len(data) < asize:
		data += b'-'
		nwords += 1
	data += suffix
	data += b'\0'
	print(nwords, 'words')
	return uleb128(nwords) + data

def patch(data):
	if b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' not in data:
		return data
	rand = random.Random(42)
	for i in range(8):
		prefix = 'x{:03}x'.format(i).encode('utf8')
		suffix = b'x'

		if i == 7:
			prefix = b'L' + prefix
			suffix += b';'
			numx = 32760-1
			gen = multiGen(rand)
		else:
			numx = 1000
			gen = simpleGen(rand, ordsets[i])

		ident = prefix + b'x'*(numx-2) + suffix
		orig = uleb128(len(ident)) + ident + b'\0'
		assert(data.count(orig) == 1)

		new = genUnicode(gen, prefix, suffix, len(orig))
		assert(len(orig) == len(new))
		data = data.replace(orig, new)
	return data

################################################################################
# Actually do the patching
def assign(s, i, j, new):
	assert(len(new) == j-i)
	return s[:i] + new + s[j:]

def fixChecksum(data):
	hashv = hashlib.sha1(data[32:]).digest()
	data = assign(data, 12, 32, hashv)

	adlrv = struct.pack('I', zlib.adler32(data[12:]) & 0xffffffff)
	return assign(data, 8, 12, adlrv)

fname, fname2 = sys.argv[1:]
with zipfile.ZipFile(fname, 'r') as z:
	with zipfile.ZipFile(fname2, 'w') as z2:
		for name in z.namelist():
			if name == 'classes.dex' or name.endswith('.RSA') or name.endswith('.SF'):
				continue
			z2.writestr(name, z.read(name), zipfile.ZIP_STORED)

		data = z.read('classes.dex')
		data2 = fixChecksum(patch(data))
		z2.writestr('classes.dex', data2, zipfile.ZIP_STORED)
