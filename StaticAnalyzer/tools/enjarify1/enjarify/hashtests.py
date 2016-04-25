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

import hashlib, os

from .main import read, translate
from .jvm.optimization import options

# Hash outputs of all tests in order to easily detect changes between versions
fullhash = b''

for i in range(1, 7):
    name = 'test{}'.format(i)
    print(name)
    dir = os.path.join('tests', name)
    rawdex = read(os.path.join(dir, 'classes.dex'), 'rb')

    for bits in range(256):
        opts = options.Options(*[bool(bits & (1 << b)) for b in range(8)])
        classes, errors = translate(rawdex, opts=opts)
        assert(not errors)

        for cls in classes.values():
            print('{:08b}'.format(bits), hashlib.sha256(cls).hexdigest())
            fullhash = hashlib.sha256(fullhash + cls).digest()

print('done!')
print('Final hash:', hashlib.sha256(fullhash).hexdigest())
