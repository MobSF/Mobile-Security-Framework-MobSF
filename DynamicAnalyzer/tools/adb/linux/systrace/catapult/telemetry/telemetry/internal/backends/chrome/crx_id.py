# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

""" Read a CRX file and write out the App ID and the Full Hash of the ID.
See: http://code.google.com/chrome/extensions/crx.html
and 'http://stackoverflow.com/questions/'
  + '1882981/google-chrome-alphanumeric-hashes-to-identify-extensions'
for docs on the format.
"""

import base64
import os
import hashlib
import json

EXPECTED_CRX_MAGIC_NUM = 'Cr24'
EXPECTED_CRX_VERSION = 2

def HexToInt(hex_chars):
  """ Convert bytes like \xab -> 171 """
  val = 0
  for i in xrange(len(hex_chars)):
    val += pow(256, i) * ord(hex_chars[i])
  return val

def HexToMPDecimal(hex_chars):
  """ Convert bytes to an MPDecimal string. Example \x00 -> "aa"
      This gives us the AppID for a chrome extension.
  """
  result = ''
  base = ord('a')
  for i in xrange(len(hex_chars)):
    value = ord(hex_chars[i])
    dig1 = value / 16
    dig2 = value % 16
    result += chr(dig1 + base)
    result += chr(dig2 + base)
  return result

def HexTo256(hex_chars):
  """ Convert bytes to pairs of hex digits. E.g., \x00\x11 -> "{0x00, 0x11}"
      The format is taylored for copy and paste into C code:
      const uint8 sha256_hash[] = { ... }; """
  result = []
  for i in xrange(len(hex_chars)):
    value = ord(hex_chars[i])
    dig1 = value / 16
    dig2 = value % 16
    result.append('0x' + hex(dig1)[2:] + hex(dig2)[2:])
  return '{%s}' % ', '.join(result)

def GetPublicKeyPacked(f):
  magic_num = f.read(4)
  if magic_num != EXPECTED_CRX_MAGIC_NUM:
    raise Exception('Invalid magic number: %s (expecting %s)' %
                    (magic_num,
                     EXPECTED_CRX_MAGIC_NUM))
  version = f.read(4)
  if not version[0] != EXPECTED_CRX_VERSION:
    raise Exception('Invalid version number: %s (expecting %s)' %
                    (version,
                     EXPECTED_CRX_VERSION))
  pub_key_len_bytes = HexToInt(f.read(4))
  f.read(4)
  return f.read(pub_key_len_bytes)

def GetPublicKeyFromPath(filepath, is_win_path=False):
  # Normalize the path for windows to have capital drive letters.
  # We intentionally don't check if sys.platform == 'win32' and just
  # check if this looks like drive letter so that we can test this
  # even on posix systems.
  if (len(filepath) >= 2 and
      filepath[0].islower() and
      filepath[1] == ':'):
    filepath = filepath[0].upper() + filepath[1:]

  # On Windows, filepaths are encoded using UTF-16, little endian byte order,
  # using "wide characters" that are 16 bits in size. On POSIX systems, the
  # encoding is generally UTF-8, which has the property of being equivalent to
  # ASCII when only ASCII characters are in the path.
  if is_win_path:
    filepath = filepath.encode('utf-16le')

  return filepath

def GetPublicKeyUnpacked(f, filepath):
  manifest = json.load(f)
  if 'key' not in manifest:
    # Use the path as the public key.
    # See Extension::GenerateIdForPath in extension.cc
    return GetPublicKeyFromPath(filepath)
  else:
    return base64.standard_b64decode(manifest['key'])

def HasPublicKey(filename):
  if os.path.isdir(filename):
    with open(os.path.join(filename, 'manifest.json'), 'rb') as f:
      manifest = json.load(f)
      return 'key' in manifest
  return False

def GetPublicKey(filename, from_file_path, is_win_path=False):
  if from_file_path:
    return GetPublicKeyFromPath(
        filename, is_win_path=is_win_path)

  pub_key = ''
  if os.path.isdir(filename):
    # Assume it's an unpacked extension
    f = open(os.path.join(filename, 'manifest.json'), 'rb')
    pub_key = GetPublicKeyUnpacked(f, filename)
    f.close()
  else:
    # Assume it's a packed extension.
    f = open(filename, 'rb')
    pub_key = GetPublicKeyPacked(f)
    f.close()
  return pub_key

def GetCRXHash(filename, from_file_path=False, is_win_path=False):
  pub_key = GetPublicKey(filename, from_file_path, is_win_path=is_win_path)
  pub_key_hash = hashlib.sha256(pub_key).digest()
  return HexTo256(pub_key_hash)

def GetCRXAppID(filename, from_file_path=False, is_win_path=False):
  pub_key = GetPublicKey(filename, from_file_path, is_win_path=is_win_path)
  pub_key_hash = hashlib.sha256(pub_key).digest()
  # AppID is the MPDecimal of only the first 128 bits of the hash.
  return HexToMPDecimal(pub_key_hash[:128/8])
