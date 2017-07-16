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
#
#
# This is a fork of the pymox library intended to work with Python 3.
# The file was modified by quermit@gmail.com and dawid.fatyga@gmail.com

"""A very basic test class derived from mox.MoxTestBase, used by test_mox.py.

The class defined in this module is used to test the features of
MoxTestBase and is not intended to be a standalone test.  It needs to
be in a separate module, because otherwise the tests in this class
(which should not all pass) would be executed as part of the
test_mox.py test suite.

See test_mox.MoxTestBaseTest for how this class is actually used.
"""

import os

from mox3 import mox


class ExampleMoxTestMixin(object):
    """Mix-in class for mox test case class.

    It stubs out the same function as one of the test methods in
    the example test case.    Both tests must pass as meta class wraps
    test methods in all base classes.
    """

    def testStat(self):
        self.mox.StubOutWithMock(os, 'stat')
        os.stat(self.DIR_PATH)
        self.mox.ReplayAll()
        os.stat(self.DIR_PATH)


class ExampleMoxTest(mox.MoxTestBase, ExampleMoxTestMixin):

    DIR_PATH = '/path/to/some/directory'

    def testSuccess(self):
        self.mox.StubOutWithMock(os, 'listdir')
        os.listdir(self.DIR_PATH)
        self.mox.ReplayAll()
        os.listdir(self.DIR_PATH)

    def testExpectedNotCalled(self):
        self.mox.StubOutWithMock(os, 'listdir')
        os.listdir(self.DIR_PATH)
        self.mox.ReplayAll()

    def testUnexpectedCall(self):
        self.mox.StubOutWithMock(os, 'listdir')
        os.listdir(self.DIR_PATH)
        self.mox.ReplayAll()
        os.listdir('/path/to/some/other/directory')
        os.listdir(self.DIR_PATH)

    def testFailure(self):
        self.assertTrue(False)

    def testStatOther(self):
        self.mox.StubOutWithMock(os, 'stat')
        os.stat(self.DIR_PATH)
        self.mox.ReplayAll()
        os.stat(self.DIR_PATH)

    def testHasStubs(self):
        listdir_list = []

        def MockListdir(directory):
            listdir_list.append(directory)

        self.stubs.Set(os, 'listdir', MockListdir)
        os.listdir(self.DIR_PATH)
        self.assertEqual([self.DIR_PATH], listdir_list)


class TestClassFromAnotherModule(object):

    def __init__(self):
        return None

    def Value(self):
        return 'Not mock'


class ChildClassFromAnotherModule(TestClassFromAnotherModule):
    """A child class of TestClassFromAnotherModule.

    Used to test stubbing out unbound methods, where child classes
    are eventually bound.
    """

    def __init__(self):
        TestClassFromAnotherModule.__init__(self)


class CallableClass(object):

    def __init__(self, one, two, nine=None):
        pass

    def __call__(self, one):
        return 'Not mock'

    def Value(self):
        return 'Not mock'


def MyTestFunction(one, two, nine=None):
    pass


class ExampleClass(object):
    def __init__(self, foo='bar'):
        pass

    def TestMethod(self, one, two, nine=None):
        pass

    def NamedParams(self, ignore, foo='bar', baz='qux'):
        pass

    def SpecialArgs(self, *args, **kwargs):
        pass


# This class is used to test stubbing out __init__ of a parent class.
class ChildExampleClass(ExampleClass):
    def __init__(self):
        ExampleClass.__init__(self)
