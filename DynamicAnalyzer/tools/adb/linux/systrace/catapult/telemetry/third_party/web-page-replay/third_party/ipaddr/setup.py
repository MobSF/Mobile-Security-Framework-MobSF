#!/usr/bin/python
#
# Copyright 2008 Google Inc.
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

from distutils.core import setup

import ipaddr


setup(name='ipaddr',
      maintainer='Google',
      maintainer_email='ipaddr-py-dev@googlegroups.com',
      version=ipaddr.__version__,
      url='http://code.google.com/p/ipaddr-py/',
      license='Apache License, Version 2.0',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries',
          'Topic :: System :: Networking'],
      py_modules=['ipaddr'])
