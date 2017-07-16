"""
Test for import machinery
"""
import unittest
import sys
import textwrap
import subprocess
import os
from modulegraph import modulegraph

class TestNativeImport (unittest.TestCase):
    # The tests check that Python's import statement
    # works as these tests expect.

    def importModule(self, name):
        if '.' in name:
            script = textwrap.dedent("""\
                try:
                    import %s
                except ImportError:
                    import %s
                print (%s.__name__)
            """) %(name, name.rsplit('.', 1)[0], name)
        else:
            script = textwrap.dedent("""\
                import %s
                print (%s.__name__)
            """) %(name, name)

        p = subprocess.Popen([sys.executable, '-c', script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    'testpkg-relimport'),
        )
        data = p.communicate()[0]
        if sys.version_info[0] != 2:
            data = data.decode('UTF-8')
        data = data.strip()

        if data.endswith(' refs]'):
            # with --with-pydebug builds
            data = data.rsplit('\n', 1)[0].strip()

        sts = p.wait()

        if sts != 0:
            print (data)
        self.assertEqual(sts, 0)
        return data


    def testRootModule(self):
        m = self.importModule('mod')
        self.assertEqual(m, 'mod')

    def testRootPkg(self):
        m = self.importModule('pkg')
        self.assertEqual(m, 'pkg')

    def testSubModule(self):
        m = self.importModule('pkg.mod')
        self.assertEqual(m, 'pkg.mod')

    if sys.version_info[0] == 2:
        def testOldStyle(self):
            m = self.importModule('pkg.oldstyle.mod')
            self.assertEqual(m, 'pkg.mod')
    else:
        # python3 always has __future__.absolute_import
        def testOldStyle(self):
            m = self.importModule('pkg.oldstyle.mod')
            self.assertEqual(m, 'mod')

    def testNewStyle(self):
        m = self.importModule('pkg.toplevel.mod')
        self.assertEqual(m, 'mod')

    def testRelativeImport(self):
        m = self.importModule('pkg.relative.mod')
        self.assertEqual(m, 'pkg.mod')

        m = self.importModule('pkg.subpkg.relative.mod')
        self.assertEqual(m, 'pkg.mod')

        m = self.importModule('pkg.subpkg.mod2.mod')
        self.assertEqual(m, 'pkg.sub2.mod')

        m = self.importModule('pkg.subpkg.relative2')
        self.assertEqual(m, 'pkg.subpkg.relative2')

class TestModuleGraphImport (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-relimport')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        #self.mf.debug = 999
        self.script_name = os.path.join(root, 'script.py')
        self.mf.run_script(self.script_name)

    def testGraphStructure(self):

        # 1. Script to imported modules
        n = self.mf.findNode(self.script_name)
        self.assertIsInstance(n, modulegraph.Script)

        imported = ('mod', 'pkg', 'pkg.mod', 'pkg.oldstyle',
            'pkg.relative', 'pkg.toplevel', 'pkg.subpkg.relative',
            'pkg.subpkg.relative2', 'pkg.subpkg.mod2')

        for nm in imported:
            n2 = self.mf.findNode(nm)
            ed = self.mf.edgeData(n, n2)
            self.assertIsInstance(ed, modulegraph.DependencyInfo)
            self.assertEqual(ed, modulegraph.DependencyInfo(
                fromlist=False, conditional=False, function=False, tryexcept=False))

        refs = self.mf.getReferences(n)
        self.assertEqual(set(refs), set(self.mf.findNode(nm) for nm in imported))

        refs = list(self.mf.getReferers(n))
        # The script is a toplevel item and is therefore referred to from the graph root (aka 'None')
        self.assertEqual(refs, [None])


        # 2. 'mod'
        n = self.mf.findNode('mod')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = list(self.mf.getReferences(n))
        self.assertEqual(refs, [])

        #refs = list(self.mf.getReferers(n))
        #self.assertEquals(refs, [])

        # 3. 'pkg'
        n = self.mf.findNode('pkg')
        self.assertIsInstance(n, modulegraph.Package)
        refs = list(self.mf.getReferences(n))
        self.maxDiff = None
        self.assertEqual(refs, [n])

        #refs = list(self.mf.getReferers(n))
        #self.assertEquals(refs, [])

        # 4. pkg.mod
        n = self.mf.findNode('pkg.mod')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('pkg')]))
        ed = self.mf.edgeData(n, self.mf.findNode('pkg'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))


        # 5. pkg.oldstyle
        n = self.mf.findNode('pkg.oldstyle')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        if sys.version_info[0] == 2:
            n2 = self.mf.findNode('pkg.mod')
        else:
            n2 = self.mf.findNode('mod')
        self.assertEqual(refs, set([self.mf.findNode('pkg'), n2]))
        ed = self.mf.edgeData(n, n2)
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))


        # 6. pkg.relative
        n = self.mf.findNode('pkg.relative')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('__future__'), self.mf.findNode('pkg'), self.mf.findNode('pkg.mod')]))

        ed = self.mf.edgeData(n, self.mf.findNode('pkg.mod'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=True, conditional=False, function=False, tryexcept=False))

        ed = self.mf.edgeData(n, self.mf.findNode('__future__'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))

        #ed = self.mf.edgeData(n, self.mf.findNode('__future__.absolute_import'))
        #self.assertIsInstance(ed, modulegraph.DependencyInfo)
        #self.assertEqual(ed, modulegraph.DependencyInfo(
            #fromlist=True, conditional=False, function=False, tryexcept=False))

        # 7. pkg.toplevel
        n = self.mf.findNode('pkg.toplevel')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('__future__'), self.mf.findNode('pkg'), self.mf.findNode('mod')]))

        ed = self.mf.edgeData(n, self.mf.findNode('mod'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))

        ed = self.mf.edgeData(n, self.mf.findNode('__future__'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))

        #ed = self.mf.edgeData(n, self.mf.findNode('__future__.absolute_import'))
        #self.assertIsInstance(ed, modulegraph.DependencyInfo)
        #self.assertEqual(ed, modulegraph.DependencyInfo(
            #fromlist=True, conditional=False, function=False, tryexcept=False))

        # 8. pkg.subpkg
        n = self.mf.findNode('pkg.subpkg')
        self.assertIsInstance(n, modulegraph.Package)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('pkg')]))

        ed = self.mf.edgeData(n, self.mf.findNode('pkg'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))

        # 9. pkg.subpkg.relative
        n = self.mf.findNode('pkg.subpkg.relative')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('__future__'), self.mf.findNode('pkg'), self.mf.findNode('pkg.subpkg'), self.mf.findNode('pkg.mod')]))

        ed = self.mf.edgeData(n, self.mf.findNode('pkg.subpkg'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=False, conditional=False, function=False, tryexcept=False))

        ed = self.mf.edgeData(n, self.mf.findNode('pkg.mod'))
        self.assertIsInstance(ed, modulegraph.DependencyInfo)
        self.assertEqual(ed, modulegraph.DependencyInfo(
            fromlist=True, conditional=False, function=False, tryexcept=False))

        # 10. pkg.subpkg.relative2
        n = self.mf.findNode('pkg.subpkg.relative2')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([self.mf.findNode('pkg.subpkg'), self.mf.findNode('pkg.relimport'), self.mf.findNode('__future__')]))

        # 10. pkg.subpkg.mod2
        n = self.mf.findNode('pkg.subpkg.mod2')
        self.assertIsInstance(n, modulegraph.SourceModule)
        refs = set(self.mf.getReferences(n))
        self.assertEqual(refs, set([
            self.mf.findNode('__future__'),
            self.mf.findNode('pkg.subpkg'),
            self.mf.findNode('pkg.sub2.mod'),
            self.mf.findNode('pkg.sub2'),
        ]))


    def testRootModule(self):
        node = self.mf.findNode('mod')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'mod')

    def testRootPkg(self):
        node = self.mf.findNode('pkg')
        self.assertIsInstance(node, modulegraph.Package)
        self.assertEqual(node.identifier, 'pkg')

    def testSubModule(self):
        node = self.mf.findNode('pkg.mod')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.mod')

    if sys.version_info[0] == 2:
        def testOldStyle(self):
            node = self.mf.findNode('pkg.oldstyle')
            self.assertIsInstance(node, modulegraph.SourceModule)
            self.assertEqual(node.identifier, 'pkg.oldstyle')
            sub = [ n for n in self.mf.get_edges(node)[0] if n.identifier != '__future__' ][0]
            self.assertEqual(sub.identifier, 'pkg.mod')
    else:
        # python3 always has __future__.absolute_import
        def testOldStyle(self):
            node = self.mf.findNode('pkg.oldstyle')
            self.assertIsInstance(node, modulegraph.SourceModule)
            self.assertEqual(node.identifier, 'pkg.oldstyle')
            sub = [ n for n in self.mf.get_edges(node)[0] if n.identifier != '__future__' ][0]
            self.assertEqual(sub.identifier, 'mod')

    def testNewStyle(self):
        node = self.mf.findNode('pkg.toplevel')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.toplevel')
        sub = [ n for n in self.mf.get_edges(node)[0] if not n.identifier.startswith('__future__')][0]
        self.assertEqual(sub.identifier, 'mod')

    def testRelativeImport(self):
        node = self.mf.findNode('pkg.relative')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.relative')
        sub = [ n for n in self.mf.get_edges(node)[0] if not n.identifier.startswith('__future__') ][0]
        self.assertIsInstance(sub, modulegraph.Package)
        self.assertEqual(sub.identifier, 'pkg')

        node = self.mf.findNode('pkg.subpkg.relative')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.subpkg.relative')
        sub = [ n for n in self.mf.get_edges(node)[0] if not n.identifier.startswith('__future__') ][0]
        self.assertIsInstance(sub, modulegraph.Package)
        self.assertEqual(sub.identifier, 'pkg')

        node = self.mf.findNode('pkg.subpkg.mod2')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.subpkg.mod2')
        sub = [ n for n in self.mf.get_edges(node)[0] if not n.identifier.startswith('__future__') ][0]
        self.assertIsInstance(sub, modulegraph.SourceModule)
        self.assertEqual(sub.identifier, 'pkg.sub2.mod')

        node = self.mf.findNode('pkg.subpkg.relative2')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(node.identifier, 'pkg.subpkg.relative2')

        node = self.mf.findNode('pkg.relimport')
        self.assertIsInstance(node, modulegraph.SourceModule)

class TestRegressions1 (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r", value, types)

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr1')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'main_script.py'))

    def testRegr1(self):
        node = self.mf.findNode('pkg.a')
        self.assertIsInstance(node, modulegraph.SourceModule)
        node = self.mf.findNode('pkg.b')
        self.assertIsInstance(node, modulegraph.SourceModule)


    def testMissingPathEntry(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'nosuchdirectory')
        try:
            mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        except os.error:
            self.fail('modulegraph initialiser raises os.error')

class TestRegressions2 (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr2')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'main_script.py'))

    def testRegr1(self):
        node = self.mf.findNode('pkg.base')
        self.assertIsInstance(node, modulegraph.SourceModule)
        node = self.mf.findNode('pkg.pkg')
        self.assertIsInstance(node, modulegraph.SourceModule)

class TestRegressions3 (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def assertStartswith(self, value, test):
        if not value.startswith(test):
            self.fail("%r does not start with %r"%(value, test))

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr3')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'script.py'))

    def testRegr1(self):
        node = self.mf.findNode('mypkg.distutils')
        self.assertIsInstance(node, modulegraph.Package)
        node = self.mf.findNode('mypkg.distutils.ccompiler')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertStartswith(node.filename, os.path.dirname(__file__))

        import distutils.sysconfig, distutils.ccompiler
        node = self.mf.findNode('distutils.ccompiler')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(os.path.dirname(node.filename),
                os.path.dirname(distutils.ccompiler.__file__))

        node = self.mf.findNode('distutils.sysconfig')
        self.assertIsInstance(node, modulegraph.SourceModule)
        self.assertEqual(os.path.dirname(node.filename),
                os.path.dirname(distutils.sysconfig.__file__))

class TestRegression4 (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr4')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'script.py'))

    def testRegr1(self):
        node = self.mf.findNode('pkg.core')
        self.assertIsInstance(node, modulegraph.Package)

        node = self.mf.findNode('pkg.core.callables')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = self.mf.findNode('pkg.core.listener')
        self.assertIsInstance(node, modulegraph.SourceModule)

        node = self.mf.findNode('pkg.core.listenerimpl')
        self.assertIsInstance(node, modulegraph.SourceModule)

class TestRegression5 (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, value, types):
            if not isinstance(value, types):
                self.fail("%r is not an instance of %r"%(value, types))

    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr5')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'script.py'))

    def testRegr1(self):
        node = self.mf.findNode('distutils')
        self.assertIsInstance(node, modulegraph.Package)
        self.assertIn('distutils/__init__', node.filename)

class TestDeeplyNested (unittest.TestCase):
    def setUp(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'testpkg-regr6')
        self.mf = modulegraph.ModuleGraph(path=[ root ] + sys.path)
        self.mf.run_script(os.path.join(root, 'script.py'))

    def testRegr(self):
        node = self.mf.findNode('os')
        self.assertTrue(node is not None)


if __name__ == "__main__":
    unittest.main()
