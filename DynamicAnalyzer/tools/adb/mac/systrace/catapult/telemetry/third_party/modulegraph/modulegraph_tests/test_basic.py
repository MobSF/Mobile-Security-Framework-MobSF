import unittest

import os, shutil

from modulegraph import modulegraph

class DummyModule(object):
    packagepath = None
    def __init__(self, ppath):
        self.packagepath = ppath

class FindAllSubmodulesTestCase(unittest.TestCase):
    def testNone(self):
        mg = modulegraph.ModuleGraph()
        # empty packagepath
        m = DummyModule(None)
        sub_ms = []
        for sm in mg._find_all_submodules(m):
            sub_ms.append(sm)
        self.assertEqual(sub_ms, [])

    def testSimple(self):
        mg = modulegraph.ModuleGraph()
        # a string does not break anything although it is split into its characters
        # BUG: "/hi/there" will read "/"
        m = DummyModule("xyz")
        sub_ms = []
        for sm in mg._find_all_submodules(m):
            sub_ms.append(sm)
        self.assertEqual(sub_ms, [])

    def testSlashes(self):
        # a string does not break anything although it is split into its characters
        # BUG: "/xyz" will read "/" so this one already triggers missing itertools
        mg = modulegraph.ModuleGraph()
        m = DummyModule("/xyz")
        sub_ms = []
        for sm in mg._find_all_submodules(m):
            sub_ms.append(sm)
        self.assertEqual(sub_ms, [])

if __name__ == '__main__':
    unittest.main()
