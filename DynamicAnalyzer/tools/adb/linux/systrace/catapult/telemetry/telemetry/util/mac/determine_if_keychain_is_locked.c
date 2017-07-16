// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This program determines whether the default OSX Keychain is unlocked without
// causing a user interaction prompt.
// Return values:
//   0 - The default keychain is unlocked.
//   1 - The default keychain is locked.
//   2 - Unexpected error.
//
// To compile, run: "clang -framework Security
//                   -o determine_if_keychain_is_locked
//                   determine_if_keychain_is_locked.c"

#include <Security/Security.h>

int main() {
  SecKeychainStatus keychain_status;
  OSStatus os_status = SecKeychainGetStatus(NULL, &keychain_status);
  if (os_status != errSecSuccess)
    return 2;

  return (keychain_status & kSecUnlockStateStatus) ? 0 : 1;
}
