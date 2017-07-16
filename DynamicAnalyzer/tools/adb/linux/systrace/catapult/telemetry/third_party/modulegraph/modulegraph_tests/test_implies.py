import unittest

import os, shutil, sys

from modulegraph import modulegraph

class ImpliesTestCase(unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, object, types, message=None):
            self.assertTrue(isinstance(object, types),
                    message or '%r is not an instance of %r'%(object, types))

    def testBasicImplies(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-relimport')

        # First check that 'syslog' isn't accidently in the graph:
        mg = modulegraph.ModuleGraph(path=[root]+sys.path)
        mg.run_script(os.path.join(root, 'script.py'))
        node = mg.findNode('mod')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = mg.findNode('syslog')
        self.assertEqual(node, None)

        # Now check that adding an implied dependency actually adds
        # 'syslog' to the graph:
        mg = modulegraph.ModuleGraph(path=[root]+sys.path, implies={
            'mod': ['syslog']})
        self.assertEqual(node, None)
        mg.run_script(os.path.join(root, 'script.py'))
        node = mg.findNode('mod')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = mg.findNode('syslog')
        self.assertIsInstance(node, modulegraph.Extension)

        # Check that the edges are correct:
        self.assertTrue(mg.findNode('mod') in mg.get_edges(node)[1])
        self.assertTrue(node in mg.get_edges(mg.findNode('mod'))[0])

    def testPackagedImplies(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-relimport')

        # First check that 'syslog' isn't accidently in the graph:
        mg = modulegraph.ModuleGraph(path=[root]+sys.path)
        mg.run_script(os.path.join(root, 'script.py'))
        node = mg.findNode('mod')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = mg.findNode('syslog')
        self.assertEqual(node, None)


        # Now check that adding an implied dependency actually adds
        # 'syslog' to the graph:
        mg = modulegraph.ModuleGraph(path=[root]+sys.path, implies={
            'pkg.relative': ['syslog']})
        node = mg.findNode('syslog')
        self.assertEqual(node, None)

        mg.run_script(os.path.join(root, 'script.py'))
        node = mg.findNode('pkg.relative')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = mg.findNode('syslog')
        self.assertIsInstance(node, modulegraph.Extension)

        # Check that the edges are correct:
        self.assertTrue(mg.findNode('pkg.relative') in mg.get_edges(node)[1])
        self.assertTrue(node in mg.get_edges(mg.findNode('pkg.relative'))[0])


if __name__ == '__main__':
    unittest.main()
