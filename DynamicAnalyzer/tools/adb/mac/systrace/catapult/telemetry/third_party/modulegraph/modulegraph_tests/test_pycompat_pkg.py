"""
Test for import machinery
"""
import unittest
import sys
import textwrap
import subprocess
import os
from modulegraph import modulegraph

class TestModuleGraphImport (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def test_compat(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-compatmodule')
        mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        mf.import_hook('pkg.api')

        node = mf.findNode('pkg')
        self.assertIsInstance(node, modulegraph.Package)

        node = mf.findNode('pkg.api')
        self.assertIsInstance(node, modulegraph.SourceModule)

        if sys.version_info[0] == 2:
            node = mf.findNode('pkg.api2')
            self.assertIsInstance(node, modulegraph.SourceModule)

            node = mf.findNode('pkg.api3')
            self.assertIsInstance(node, modulegraph.InvalidSourceModule)

            node = mf.findNode('http.client')
            self.assertIs(node, None)

            node = mf.findNode('urllib2')
            self.assertIsInstance(node, modulegraph.SourceModule)

        else:
            node = mf.findNode('pkg.api2')
            self.assertIsInstance(node, modulegraph.InvalidSourceModule)

            node = mf.findNode('pkg.api3')
            self.assertIsInstance(node, modulegraph.SourceModule)

            node = mf.findNode('http.client')
            self.assertIsInstance(node, modulegraph.SourceModule)

            node = mf.findNode('urllib2')
            self.assertIs(node, None)




if __name__ == "__main__":
    unittest.main()
