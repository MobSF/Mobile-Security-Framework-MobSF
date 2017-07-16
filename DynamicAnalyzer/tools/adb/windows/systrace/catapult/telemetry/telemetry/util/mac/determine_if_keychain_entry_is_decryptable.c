// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This program determines whether a specific entry in the default OSX Keychain
// is decryptable by all applications without a user prompt.
//
// This program uses APIs only available on OSX 10.7+.
//
// Input format:
//  determine_if_keychain_entry_is_decryptable [service name] [account name]
//
// Return values:
//   0 - The entry doesn't exist, or the ACLs are correct.
//   1 - The ACLs are incorrect.
//   >=2 - Unexpected error.
//
// To compile, run: "clang -framework Security -framework CoreFoundation
//                   -o determine_if_keychain_entry_is_decryptable
//                   determine_if_keychain_entry_is_decryptable.c"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>

int main(int argc, char* argv[]) {
  // There must be exactly 2 arguments to the program.
  if (argc != 3)
    return 2;

  const char* service_name = argv[1];
  const char* account_name = argv[2];
  SecKeychainItemRef item;
  OSStatus status = SecKeychainFindGenericPassword(NULL, strlen(service_name),
      service_name, strlen(account_name), account_name, NULL, NULL, &item);

  // There is no keychain item.
  if (status == errSecItemNotFound)
    return 0;

  // Unexpected error.
  if (status != errSecSuccess)
    return 3;

  SecAccessRef access;
  status = SecKeychainItemCopyAccess(item, &access);

  // Unexpected error.
  if (status != errSecSuccess) {
    CFRelease(access);
    CFRelease(item);
    return 4;
  }

  CFArrayRef acl_list =
      SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);

  for (CFIndex i = 0; i < CFArrayGetCount(acl_list); ++i) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, i);

    CFArrayRef application_list;
    CFStringRef description;
    SecKeychainPromptSelector prompt_selector;
    status = SecACLCopyContents(acl, &application_list, &description,
                                &prompt_selector);

    // Unexpected error.
    if (status != errSecSuccess) {
      CFRelease(acl_list);
      CFRelease(access);
      CFRelease(item);
      return 5;
    }

    // Check whether this acl gives decryption access to all applications.
    bool found_correct_acl = (application_list == NULL);
    CFRelease(description);
    if (application_list)
      CFRelease(application_list);

    if (found_correct_acl) {
      CFRelease(acl_list);
      CFRelease(access);
      CFRelease(item);
      return 0;
    }
  }

  // No acl was found that gave decryption access to all applications.
  CFRelease(acl_list);
  CFRelease(access);
  CFRelease(item);
  return 1;
}
