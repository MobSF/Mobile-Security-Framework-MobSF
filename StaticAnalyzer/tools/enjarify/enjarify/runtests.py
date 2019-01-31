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

import zipfile, os, subprocess

from .main import read, translate, writeToJar
from .jvm.optimization import options

def getStubs():
    with zipfile.ZipFile('tests/stubs/stubs.zip', 'r') as stubs:
        for name in stubs.namelist():
            yield (name, stubs.read(name))
STUB_FILES = dict(getStubs())

def executeTest(name, opts):
    print('running test', name)
    dir = os.path.join('tests', name)
    rawdex = read(os.path.join(dir, 'classes.dex'), 'rb')
    classes, errors = translate(rawdex, opts=opts)
    assert(not errors)

    classes.update(STUB_FILES)
    writeToJar('out.jar', classes)

    result = subprocess.check_output("java -Xss515m -jar out.jar a.a".split(),
        stderr=subprocess.STDOUT,
        universal_newlines=True)
    expected = read(os.path.join(dir, 'expected.txt'), 'r')
    assert(result == expected)


for opts in [options.NONE, options.PRETTY, options.ALL]:
    for i in range(1, 7):
        executeTest('test{}'.format(i), opts)
print('all tests passed!')
