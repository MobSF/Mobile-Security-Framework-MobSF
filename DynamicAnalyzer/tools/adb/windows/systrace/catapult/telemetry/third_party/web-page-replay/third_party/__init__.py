# Copyright 2010 Google Inc. All Rights Reserved.
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

import os
import sys

try:
    __file__
except NameError:
    __file__ = sys.argv[0]
third_party_dir = os.path.dirname(os.path.abspath(__file__))
ipaddr_dir = os.path.join(third_party_dir, "ipaddr")
sys.path.append(ipaddr_dir)  # workaround for no __init__.py
import ipaddr

# Modules in dns/ import sibling modules by "import dns/xxx", but
# some platform has dns/ in global site-packages directory so we need to raise
# the precedence of local search path (crbug/493869).
# The implementation here preloads all dns/ modules into this package so clients
# don't need to worry about import path issue.
# An easier solution might be modify dns/ modules to use relative path, but I
# tried not to touch third_party lib for now.
sys.path.insert(0, third_party_dir)
from dns import __all__ as all_dns_modules
all_dns_modules = ['dns.' + m for m in  all_dns_modules]
map(__import__, all_dns_modules)
sys.path.pop(0)
