# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import fixtures
from mox3 import mox
from mox3 import stubout


class MoxStubout(fixtures.Fixture):
    """Deal with code around mox and stubout as a fixture."""

    def setUp(self):
        super(MoxStubout, self).setUp()
        self.mox = mox.Mox()
        self.stubs = stubout.StubOutForTesting()
        self.addCleanup(self.mox.UnsetStubs)
        self.addCleanup(self.stubs.UnsetAll)
        self.addCleanup(self.stubs.SmartUnsetAll)
        self.addCleanup(self.mox.VerifyAll)
