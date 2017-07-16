#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Creates a distributable python package.

Creating new packages:
  1. Generate the package, dist/webpagereplay-X.X.tar.gz:
       python setup.py sdist
  2. Upload the package file to the following:
       http://code.google.com/p/web-page-replay/downloads/entry

Installing packages:
  $ easy_install http://web-page-replay.googlecode.com/files/webpagereplay-X.X.tar.gz
  - The replay and httparchive commands are now on your PATH.
"""

import setuptools

setuptools.setup(
    name='webpagereplay',
    version='1.1.2',
    description='Record and replay web content',
    author='Web Page Replay Project Authors',
    author_email='web-page-replay-dev@googlegroups.com',
    url='http://code.google.com/p/web-page-replay/',
    license='Apache License 2.0',
    install_requires=['dnspython>=1.8'],
    packages=[
        '',
        'third_party',
        'third_party.ipaddr'
        ],
    package_dir={'': '.'},
    package_data={
        '': ['*.js', '*.txt', 'COPYING', 'LICENSE'],
        },
    entry_points={
        'console_scripts': [
            'httparchive = httparchive:main',
            'replay = replay:main',
            ]
        },
    )
