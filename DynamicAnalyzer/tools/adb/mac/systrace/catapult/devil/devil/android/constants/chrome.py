# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

PackageInfo = collections.namedtuple(
    'PackageInfo',
    ['package', 'activity', 'cmdline_file', 'devtools_socket'])

PACKAGE_INFO = {
    'chrome_document': PackageInfo(
        'com.google.android.apps.chrome.document',
        'com.google.android.apps.chrome.document.ChromeLauncherActivity',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome': PackageInfo(
        'com.google.android.apps.chrome',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome_beta': PackageInfo(
        'com.chrome.beta',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome_stable': PackageInfo(
        'com.android.chrome',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome_dev': PackageInfo(
        'com.chrome.dev',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome_canary': PackageInfo(
        'com.chrome.canary',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chrome_work': PackageInfo(
        'com.chrome.work',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'chromium': PackageInfo(
        'org.chromium.chrome',
        'com.google.android.apps.chrome.Main',
        'chrome-command-line',
        'chrome_devtools_remote'),
    'content_shell': PackageInfo(
        'org.chromium.content_shell_apk',
        '.ContentShellActivity',
        'content-shell-command-line',
        'content_shell_devtools_remote'),
}
