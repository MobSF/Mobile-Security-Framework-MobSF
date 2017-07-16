import unittest
from modulegraph import modulegraph
import pkg_resources
import os
import imp
import sys
import shutil
import warnings
from altgraph import Graph
import textwrap
import xml.etree.ElementTree as ET
import pickle

try:
    bytes
except NameError:
    bytes = str

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

TESTDATA = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "testdata", "nspkg")

try:
    expectedFailure = unittest.expectedFailure
except AttributeError:
    import functools
    def expectedFailure(function):
        @functools.wraps(function)
        def wrapper(*args, **kwds):
            try:
                function(*args, **kwds)
            except AssertionError:
                pass

            else:
                self.fail("unexpected pass")

class TestDependencyInfo (unittest.TestCase):
    def test_pickling(self):
        info = modulegraph.DependencyInfo(function=True, conditional=False, tryexcept=True, fromlist=False)
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            b = pickle.dumps(info, proto)
            self.assertTrue(isinstance(b, bytes))

            o = pickle.loads(b)
            self.assertEqual(o, info)

    def test_merging(self):
        info1 = modulegraph.DependencyInfo(function=True, conditional=False, tryexcept=True, fromlist=False)
        info2 = modulegraph.DependencyInfo(function=False, conditional=True, tryexcept=True, fromlist=False)
        self.assertEqual(
            info1._merged(info2), modulegraph.DependencyInfo(function=True, conditional=True, tryexcept=True, fromlist=False))

        info2 = modulegraph.DependencyInfo(function=False, conditional=True, tryexcept=False, fromlist=False)
        self.assertEqual(
            info1._merged(info2), modulegraph.DependencyInfo(function=True, conditional=True, tryexcept=True, fromlist=False))

        info2 = modulegraph.DependencyInfo(function=False, conditional=False, tryexcept=False, fromlist=False)
        self.assertEqual(
            info1._merged(info2), modulegraph.DependencyInfo(function=False, conditional=False, tryexcept=False, fromlist=False))

        info1 = modulegraph.DependencyInfo(function=True, conditional=False, tryexcept=True, fromlist=True)
        self.assertEqual(
            info1._merged(info2), modulegraph.DependencyInfo(function=False, conditional=False, tryexcept=False, fromlist=False))

        info2 = modulegraph.DependencyInfo(function=False, conditional=False, tryexcept=False, fromlist=True)
        self.assertEqual(
            info1._merged(info2), modulegraph.DependencyInfo(function=False, conditional=False, tryexcept=False, fromlist=True))


class TestFunctions (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, types):
            self.assertTrue(isinstance(obj, types), '%r is not instance of %r'%(obj, types))

    def test_eval_str_tuple(self):
        for v in [
            '()',
            '("hello",)',
            '("hello", "world")',
            "('hello',)",
            "('hello', 'world')",
            "('hello', \"world\")",
            ]:

            self.assertEqual(modulegraph._eval_str_tuple(v), eval(v))

        self.assertRaises(ValueError, modulegraph._eval_str_tuple, "")
        self.assertRaises(ValueError, modulegraph._eval_str_tuple, "'a'")
        self.assertRaises(ValueError, modulegraph._eval_str_tuple, "'a', 'b'")
        self.assertRaises(ValueError, modulegraph._eval_str_tuple, "('a', ('b', 'c'))")
        self.assertRaises(ValueError, modulegraph._eval_str_tuple, "('a', ('b\", 'c'))")

    def test_namespace_package_path(self):
        class DS (object):
            def __init__(self, path, namespace_packages=None):
                self.location = path
                self._namespace_packages = namespace_packages

            def has_metadata(self, key):
                if key == 'namespace_packages.txt':
                    return self._namespace_packages is not None

                raise ValueError("invalid lookup key")

            def get_metadata(self, key):
                if key == 'namespace_packages.txt':
                    if self._namespace_packages is None:
                        raise ValueError("no file")

                    return self._namespace_packages

                raise ValueError("invalid lookup key")

        class WS (object):
            def __init__(self, path=None):
                pass

            def __iter__(self):
                yield DS("/pkg/pkg1")
                yield DS("/pkg/pkg2", "foo\n")
                yield DS("/pkg/pkg3", "bar.baz\n")
                yield DS("/pkg/pkg4", "foobar\nfoo\n")

        saved_ws = pkg_resources.WorkingSet
        try:
            pkg_resources.WorkingSet = WS

            self.assertEqual(modulegraph._namespace_package_path("sys", ["appdir/pkg"]), ["appdir/pkg"])
            self.assertEqual(modulegraph._namespace_package_path("foo", ["appdir/pkg"]), ["appdir/pkg", "/pkg/pkg2/foo", "/pkg/pkg4/foo"])
            self.assertEqual(modulegraph._namespace_package_path("bar.baz", ["appdir/pkg"]), ["appdir/pkg", "/pkg/pkg3/bar/baz"])

        finally:
            pkg_resources.WorkingSet = saved_ws

    def test_os_listdir(self):
        root = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'testdata')

        self.assertEqual(modulegraph.os_listdir('/etc/'), os.listdir('/etc'))
        self.assertRaises(IOError, modulegraph.os_listdir, '/etc/hosts/foobar')
        self.assertRaises(IOError, modulegraph.os_listdir, os.path.join(root, 'test.egg', 'bar'))

        self.assertEqual(list(sorted(modulegraph.os_listdir(os.path.join(root, 'test.egg', 'foo')))),
            [ 'bar', 'bar.txt', 'baz.txt' ])

    def test_code_to_file(self):
        try:
            code = modulegraph._code_to_file.__code__
        except AttributeError:
            code = modulegraph._code_to_file.func_code

        data = modulegraph._code_to_file(code)
        self.assertTrue(hasattr(data, 'read'))

        content = data.read()
        self.assertIsInstance(content, bytes)
        data.close()

    def test_find_module(self):
        for path in ('syspath', 'syspath.zip', 'syspath.egg'):
            path = os.path.join(os.path.dirname(TESTDATA), path)
            if os.path.exists(os.path.join(path, 'mymodule.pyc')):
                os.unlink(os.path.join(path, 'mymodule.pyc'))

            # Plain module
            info = modulegraph.find_module('mymodule', path=[path] + sys.path)

            fp = info[0]
            filename = info[1]
            description = info[2]

            self.assertTrue(hasattr(fp, 'read'))

            if path.endswith('.zip') or path.endswith('.egg'):
                # Zip importers may precompile
                if filename.endswith('.py'):
                    self.assertEqual(filename, os.path.join(path, 'mymodule.py'))
                    self.assertEqual(description, ('.py', 'rU', imp.PY_SOURCE))

                else:
                    self.assertEqual(filename, os.path.join(path, 'mymodule.pyc'))
                    self.assertEqual(description, ('.pyc', 'rb', imp.PY_COMPILED))

            else:
                self.assertEqual(filename, os.path.join(path, 'mymodule.py'))
                self.assertEqual(description, ('.py', 'rU', imp.PY_SOURCE))

            # Compiled plain module, no source
            if path.endswith('.zip') or path.endswith('.egg'):
                self.assertRaises(ImportError, modulegraph.find_module, 'mymodule2', path=[path] + sys.path)

            else:
                info = modulegraph.find_module('mymodule2', path=[path] + sys.path)

                fp = info[0]
                filename = info[1]
                description = info[2]

                self.assertTrue(hasattr(fp, 'read'))
                self.assertEqual(filename, os.path.join(path, 'mymodule2.pyc'))
                self.assertEqual(description, ('.pyc', 'rb', imp.PY_COMPILED))

                fp.close()

            # Compiled plain module, with source
#            info = modulegraph.find_module('mymodule3', path=[path] + sys.path)
#
#            fp = info[0]
#            filename = info[1]
#            description = info[2]
#
#            self.assertTrue(hasattr(fp, 'read'))
#
#            if sys.version_info[:2] >= (3,2):
#                self.assertEqual(filename, os.path.join(path, '__pycache__', 'mymodule3.cpython-32.pyc'))
#            else:
#                self.assertEqual(filename, os.path.join(path, 'mymodule3.pyc'))
#            self.assertEqual(description, ('.pyc', 'rb', imp.PY_COMPILED))


            # Package
            info = modulegraph.find_module('mypkg', path=[path] + sys.path)
            fp = info[0]
            filename = info[1]
            description = info[2]

            self.assertEqual(fp, None)
            self.assertEqual(filename, os.path.join(path, 'mypkg'))
            self.assertEqual(description, ('', '', imp.PKG_DIRECTORY))

            # Extension
            if path.endswith('.zip'):
                self.assertRaises(ImportError, modulegraph.find_module, 'myext', path=[path] + sys.path)

            else:
                info = modulegraph.find_module('myext', path=[path] + sys.path)
                fp = info[0]
                filename = info[1]
                description = info[2]

                if sys.platform == 'win32':
                    ext = '.pyd'
                else:
                    # This is a ly, but is good enough for now
                    ext = '.so'

                self.assertEqual(filename, os.path.join(path, 'myext' + ext))
                self.assertEqual(description, (ext, 'rb', imp.C_EXTENSION))
                self.assertEqual(fp, None)

    def test_moduleInfoForPath(self):
        self.assertEqual(modulegraph.moduleInfoForPath("/somewhere/else/file.txt"), None)

        info = modulegraph.moduleInfoForPath("/somewhere/else/file.py")
        self.assertEqual(info[0], "file")
        if sys.version_info[:2] >= (3,4):
            self.assertEqual(info[1], "r")
        else:
            self.assertEqual(info[1], "U")
        self.assertEqual(info[2], imp.PY_SOURCE)

        info = modulegraph.moduleInfoForPath("/somewhere/else/file.pyc")
        self.assertEqual(info[0], "file")
        self.assertEqual(info[1], "rb")
        self.assertEqual(info[2], imp.PY_COMPILED)

        if sys.platform in ('darwin', 'linux2'):
            info = modulegraph.moduleInfoForPath("/somewhere/else/file.so")
            self.assertEqual(info[0], "file")
            self.assertEqual(info[1], "rb")
            self.assertEqual(info[2], imp.C_EXTENSION)

        elif sys.platform in ('win32',):
            info = modulegraph.moduleInfoForPath("/somewhere/else/file.pyd")
            self.assertEqual(info[0], "file")
            self.assertEqual(info[1], "rb")
            self.assertEqual(info[2], imp.C_EXTENSION)

    if sys.version_info[:2] > (2,5):
        exec(textwrap.dedent('''\
            def test_deprecated(self):
                saved_add = modulegraph.addPackagePath
                saved_replace = modulegraph.replacePackage
                try:
                    called = []

                    def log_add(*args, **kwds):
                        called.append(('add', args, kwds))
                    def log_replace(*args, **kwds):
                        called.append(('replace', args, kwds))

                    modulegraph.addPackagePath = log_add
                    modulegraph.replacePackage = log_replace

                    with warnings.catch_warnings(record=True) as w:
                        warnings.simplefilter("always")
                        modulegraph.ReplacePackage('a', 'b')
                        modulegraph.AddPackagePath('c', 'd')

                    self.assertEqual(len(w), 2)
                    self.assertTrue(w[-1].category is DeprecationWarning)
                    self.assertTrue(w[-2].category is DeprecationWarning)

                    self.assertEqual(called, [
                        ('replace', ('a', 'b'), {}),
                        ('add', ('c', 'd'), {}),
                    ])

                finally:
                    modulegraph.addPackagePath = saved_add
                    modulegraph.replacePackage = saved_replace
            '''), locals(), globals())

    def test_addPackage(self):
        saved = modulegraph._packagePathMap
        self.assertIsInstance(saved, dict)
        try:
            modulegraph._packagePathMap = {}

            modulegraph.addPackagePath('foo', 'a')
            self.assertEqual(modulegraph._packagePathMap, { 'foo': ['a'] })

            modulegraph.addPackagePath('foo', 'b')
            self.assertEqual(modulegraph._packagePathMap, { 'foo': ['a', 'b'] })

            modulegraph.addPackagePath('bar', 'b')
            self.assertEqual(modulegraph._packagePathMap, { 'foo': ['a', 'b'], 'bar': ['b'] })

        finally:
            modulegraph._packagePathMap = saved


    def test_replacePackage(self):
        saved = modulegraph._replacePackageMap
        self.assertIsInstance(saved, dict)
        try:
            modulegraph._replacePackageMap = {}

            modulegraph.replacePackage("a", "b")
            self.assertEqual(modulegraph._replacePackageMap, {"a": "b"})
            modulegraph.replacePackage("a", "c")
            self.assertEqual(modulegraph._replacePackageMap, {"a": "c"})
            modulegraph.replacePackage("b", "c")
            self.assertEqual(modulegraph._replacePackageMap, {"a": "c", 'b': 'c'})

        finally:
            modulegraph._replacePackageMap = saved

class TestNode (unittest.TestCase):
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, types):
            self.assertTrue(isinstance(obj, types), '%r is not instance of %r'%(obj, types))
    def testBasicAttributes(self):
        n = modulegraph.Node("foobar.xyz")
        self.assertIsInstance(n.debug, int)
        self.assertEqual(n.identifier, n.graphident)
        self.assertEqual(n.identifier, 'foobar.xyz')
        self.assertEqual(n.filename, None)
        self.assertEqual(n.packagepath, None)
        self.assertEqual(n.code, None)
        self.assertEqual(n.globalnames, set())
        self.assertEqual(n.starimports, set())

    def testMapping(self):
        n = modulegraph.Node("foobar.xyz")
        self.assertEqual(n._namespace, {})

        self.assertFalse('foo' in n)
        self.assertRaises(KeyError, n.__getitem__, 'foo')
        self.assertEqual(n.get('foo'), None)
        self.assertEqual(n.get('foo', 'a'), 'a')
        n['foo'] = 42
        self.assertEqual(n['foo'], 42)
        self.assertTrue('foo' in n)
        self.assertEqual(n._namespace, {'foo':42})

    def testOrder(self):
        n1 = modulegraph.Node("n1")
        n2 = modulegraph.Node("n2")

        self.assertTrue(n1 < n2)
        self.assertFalse(n2 < n1)
        self.assertTrue(n1 <= n1)
        self.assertFalse(n1 == n2)
        self.assertTrue(n1 == n1)
        self.assertTrue(n1 != n2)
        self.assertFalse(n1 != n1)
        self.assertTrue(n2 > n1)
        self.assertFalse(n1 > n2)
        self.assertTrue(n1 >= n1)
        self.assertTrue(n2 >= n1)

    def testHashing(self):
        n1a = modulegraph.Node('n1')
        n1b = modulegraph.Node('n1')
        n2 = modulegraph.Node('n2')

        d = {}
        d[n1a] = 'n1'
        d[n2] = 'n2'
        self.assertEqual(d[n1b], 'n1')
        self.assertEqual(d[n2], 'n2')

    def test_infoTuple(self):
        n = modulegraph.Node('n1')
        self.assertEqual(n.infoTuple(), ('n1',))

    def assertNoMethods(self, klass):
        d = dict(klass.__dict__)
        del d['__doc__']
        del d['__module__']
        if '__qualname__' in d:
            # New in Python 3.3
            del d['__qualname__']
        if '__dict__' in d:
            # New in Python 3.4
            del d['__dict__']
        self.assertEqual(d, {})

    def assertHasExactMethods(self, klass, *methods):
        d = dict(klass.__dict__)
        del d['__doc__']
        del d['__module__']
        if '__qualname__' in d:
            # New in Python 3.3
            del d['__qualname__']
        if '__dict__' in d:
            # New in Python 3.4
            del d['__dict__']

        for nm in methods:
            self.assertTrue(nm in d, "%s doesn't have attribute %r"%(klass, nm))
            del d[nm]

        self.assertEqual(d, {})


    if not hasattr(unittest.TestCase, 'assertIsSubclass'):
        def assertIsSubclass(self, cls1, cls2, message=None):
            self.assertTrue(issubclass(cls1, cls2),
                    message or "%r is not a subclass of %r"%(cls1, cls2))

    def test_subclasses(self):
        self.assertIsSubclass(modulegraph.AliasNode, modulegraph.Node)
        self.assertIsSubclass(modulegraph.Script, modulegraph.Node)
        self.assertIsSubclass(modulegraph.BadModule, modulegraph.Node)
        self.assertIsSubclass(modulegraph.ExcludedModule, modulegraph.BadModule)
        self.assertIsSubclass(modulegraph.MissingModule, modulegraph.BadModule)
        self.assertIsSubclass(modulegraph.BaseModule, modulegraph.Node)
        self.assertIsSubclass(modulegraph.BuiltinModule, modulegraph.BaseModule)
        self.assertIsSubclass(modulegraph.SourceModule, modulegraph.BaseModule)
        self.assertIsSubclass(modulegraph.CompiledModule, modulegraph.BaseModule)
        self.assertIsSubclass(modulegraph.Package, modulegraph.BaseModule)
        self.assertIsSubclass(modulegraph.Extension, modulegraph.BaseModule)

        # These classes have no new functionality, check that no code
        # got added:
        self.assertNoMethods(modulegraph.BadModule)
        self.assertNoMethods(modulegraph.ExcludedModule)
        self.assertNoMethods(modulegraph.MissingModule)
        self.assertNoMethods(modulegraph.BuiltinModule)
        self.assertNoMethods(modulegraph.SourceModule)
        self.assertNoMethods(modulegraph.CompiledModule)
        self.assertNoMethods(modulegraph.Package)
        self.assertNoMethods(modulegraph.Extension)

        # AliasNode is basicly a clone of an existing node
        self.assertHasExactMethods(modulegraph.Script, '__init__', 'infoTuple')
        n1 = modulegraph.Node('n1')
        n1.packagepath = ['a', 'b']

        a1 = modulegraph.AliasNode('a1', n1)
        self.assertEqual(a1.graphident, 'a1')
        self.assertEqual(a1.identifier, 'n1')
        self.assertTrue(a1.packagepath is n1.packagepath)
        self.assertTrue(a1._namespace is n1._namespace)
        self.assertTrue(a1.globalnames is n1.globalnames)
        self.assertTrue(a1.starimports is n1.starimports)

        v = a1.infoTuple()
        self.assertEqual(v, ('a1', 'n1'))

        # Scripts have a filename
        self.assertHasExactMethods(modulegraph.Script, '__init__', 'infoTuple')
        s1 = modulegraph.Script('do_import')
        self.assertEqual(s1.graphident, 'do_import')
        self.assertEqual(s1.identifier, 'do_import')
        self.assertEqual(s1.filename, 'do_import')

        v = s1.infoTuple()
        self.assertEqual(v, ('do_import',))

        # BaseModule adds some attributes and a custom infotuple
        self.assertHasExactMethods(modulegraph.BaseModule, '__init__', 'infoTuple')
        m1 = modulegraph.BaseModule('foo')
        self.assertEqual(m1.graphident, 'foo')
        self.assertEqual(m1.identifier, 'foo')
        self.assertEqual(m1.filename, None)
        self.assertEqual(m1.packagepath, None)

        m1 = modulegraph.BaseModule('foo', 'bar',  ['a'])
        self.assertEqual(m1.graphident, 'foo')
        self.assertEqual(m1.identifier, 'foo')
        self.assertEqual(m1.filename, 'bar')
        self.assertEqual(m1.packagepath, ['a'])

class TestModuleGraph (unittest.TestCase):
    # Test for class modulegraph.modulegraph.ModuleGraph
    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, types):
            self.assertTrue(isinstance(obj, types), '%r is not instance of %r'%(obj, types))

    def test_constructor(self):
        o = modulegraph.ModuleGraph()
        self.assertTrue(o.path is sys.path)
        self.assertEqual(o.lazynodes, {})
        self.assertEqual(o.replace_paths, ())
        self.assertEqual(o.debug, 0)

        # Stricter tests would be nice, but that requires
        # better control over what's on sys.path
        self.assertIsInstance(o.nspackages, dict)

        g = Graph.Graph()
        o = modulegraph.ModuleGraph(['a', 'b', 'c'], ['modA'], [
                ('fromA', 'toB'), ('fromC', 'toD')],
                {
                    'modA': ['modB', 'modC'],
                    'modC': ['modE', 'modF'],
                }, g, 1)
        self.assertEqual(o.path, ['a', 'b', 'c'])
        self.assertEqual(o.lazynodes, {
            'modA': None,
            'modC': ['modE', 'modF'],
        })
        self.assertEqual(o.replace_paths, [('fromA', 'toB'), ('fromC', 'toD')])
        self.assertEqual(o.nspackages, {})
        self.assertTrue(o.graph is g)
        self.assertEqual(o.debug, 1)

    def test_calc_setuptools_nspackages(self):
        stdlib = [ fn for fn in sys.path if fn.startswith(sys.prefix) and 'site-packages' not in fn ]
        for subdir in [ nm for nm in os.listdir(TESTDATA) if nm != 'src' ]:
            graph = modulegraph.ModuleGraph(path=[
                    os.path.join(TESTDATA, subdir, "parent"),
                    os.path.join(TESTDATA, subdir, "child"),
                ] + stdlib)

            pkgs = graph.nspackages
            self.assertTrue('namedpkg' in pkgs)
            self.assertEqual(set(pkgs['namedpkg']),
                    set([
                        os.path.join(TESTDATA, subdir, "parent", "namedpkg"),
                        os.path.join(TESTDATA, subdir, "child", "namedpkg"),
                    ]))
            self.assertFalse(os.path.exists(os.path.join(TESTDATA, subdir, "parent", "namedpkg", "__init__.py")))
            self.assertFalse(os.path.exists(os.path.join(TESTDATA, subdir, "child", "namedpkg", "__init__.py")))

    def testImpliedReference(self):
        graph = modulegraph.ModuleGraph()

        record = []
        def import_hook(*args):
            record.append(('import_hook',) + args)
            return [graph.createNode(modulegraph.Node, args[0])]

        def _safe_import_hook(*args):
            record.append(('_safe_import_hook',) + args)
            return [graph.createNode(modulegraph.Node, args[0])]

        graph.import_hook = import_hook
        graph._safe_import_hook = _safe_import_hook

        n1 = graph.createNode(modulegraph.Node, 'n1')
        n2 = graph.createNode(modulegraph.Node, 'n2')

        graph.implyNodeReference(n1, n2)
        outs, ins = map(list, graph.get_edges(n1))
        self.assertEqual(outs, [n2])
        self.assertEqual(ins, [])

        self.assertEqual(record, [])

        graph.implyNodeReference(n2, "n3")
        n3 = graph.findNode('n3')
        outs, ins = map(list, graph.get_edges(n2))
        self.assertEqual(outs, [n3])
        self.assertEqual(ins, [n1])
        self.assertEqual(record, [
            ('_safe_import_hook', 'n3', n2, None)
        ])



    @expectedFailure
    def test_findNode(self):
        self.fail("findNode")

    def test_run_script(self):
        script = os.path.join(os.path.dirname(TESTDATA), 'script')

        graph = modulegraph.ModuleGraph()
        master = graph.createNode(modulegraph.Node, 'root')
        m = graph.run_script(script, master)
        self.assertEqual(list(graph.get_edges(master)[0])[0], m)
        self.assertEqual(set(graph.get_edges(m)[0]), set([
            graph.findNode('sys'),
            graph.findNode('os'),
        ]))

    @expectedFailure
    def test_import_hook(self):
        self.fail("import_hook")

    def test_determine_parent(self):
        graph = modulegraph.ModuleGraph()
        graph.import_hook('os.path', None)
        graph.import_hook('idlelib', None)
        graph.import_hook('xml.dom', None)

        for node in graph.nodes():
            if isinstance(node, modulegraph.Package):
                break
        else:
            self.fail("No package located, should have at least 'os'")

        self.assertIsInstance(node, modulegraph.Package)
        parent = graph._determine_parent(node)
        self.assertEqual(parent.identifier, node.identifier)
        self.assertEqual(parent, graph.findNode(node.identifier))
        self.assertTrue(isinstance(parent, modulegraph.Package))

        # XXX: Might be a usecase for some odd code in determine_parent...
        #node = modulegraph.Package('encodings')
        #node.packagepath = parent.packagepath
        #m = graph._determine_parent(node)
        #self.assertTrue(m is parent)

        m = graph.findNode('xml')
        self.assertEqual(graph._determine_parent(m), m)

        m = graph.findNode('xml.dom')
        self.assertEqual(graph._determine_parent(m), graph.findNode('xml.dom'))


    @expectedFailure
    def test_find_head_package(self):
        self.fail("find_head_package")

    def test_load_tail(self):
        # XXX: This test is dodgy!
        graph = modulegraph.ModuleGraph()

        record = []
        def _import_module(partname, fqname, parent):
            record.append((partname, fqname, parent))
            if partname == 'raises' or '.raises.' in fqname:
                return None
            return modulegraph.Node(fqname)

        graph._import_module = _import_module

        record = []
        root = modulegraph.Node('root')
        m = graph._load_tail(root, '')
        self.assertTrue(m is root)
        self.assertEqual(record, [
            ])

        record = []
        root = modulegraph.Node('root')
        m = graph._load_tail(root, 'sub')
        self.assertFalse(m is root)
        self.assertEqual(record, [
                ('sub', 'root.sub', root),
            ])

        record = []
        root = modulegraph.Node('root')
        m = graph._load_tail(root, 'sub.sub1')
        self.assertFalse(m is root)
        node = modulegraph.Node('root.sub')
        self.assertEqual(record, [
                ('sub', 'root.sub', root),
                ('sub1', 'root.sub.sub1', node),
            ])

        record = []
        root = modulegraph.Node('root')
        m = graph._load_tail(root, 'sub.sub1.sub2')
        self.assertFalse(m is root)
        node = modulegraph.Node('root.sub')
        node2 = modulegraph.Node('root.sub.sub1')
        self.assertEqual(record, [
                ('sub', 'root.sub', root),
                ('sub1', 'root.sub.sub1', node),
                ('sub2', 'root.sub.sub1.sub2', node2),
            ])

        n = graph._load_tail(root, 'raises')
        self.assertIsInstance(n, modulegraph.MissingModule)
        self.assertEqual(n.identifier, 'root.raises')

        n = graph._load_tail(root, 'sub.raises')
        self.assertIsInstance(n, modulegraph.MissingModule)
        self.assertEqual(n.identifier, 'root.sub.raises')

        n = graph._load_tail(root, 'sub.raises.sub')
        self.assertIsInstance(n, modulegraph.MissingModule)
        self.assertEqual(n.identifier, 'root.sub.raises.sub')



    @expectedFailure
    def test_ensure_fromlist(self):
        # 1. basic 'from module import name, name'
        # 2. 'from module import *'
        # 3. from module import os
        #    (where 'os' is not a name in 'module',
        #     should create MissingModule node, and
        #     should *not* refer to the global os)
        self.fail("ensure_fromlist")

    @expectedFailure
    def test_find_all_submodules(self):
        # 1. basic
        # 2. no packagepath (basic module)
        # 3. extensions, python modules
        # 4. with/without zipfile
        # 5. files that aren't python modules/extensions
        self.fail("find_all_submodules")

    @expectedFailure
    def test_import_module(self):
        self.fail("import_module")

    @expectedFailure
    def test_load_module(self):
        self.fail("load_module")

    @expectedFailure
    def test_safe_import_hook(self):
        self.fail("safe_import_hook")

    @expectedFailure
    def test_scan_code(self):
        mod = modulegraph.Node('root')

        graph = modulegraph.ModuleGraph()
        code = compile('', '<test>', 'exec', 0, False)
        graph.scan_code(code, mod)
        self.assertEqual(list(graph.nodes()), [])

        node_map = {}
        def _safe_import(name, mod, fromlist, level):
            if name in node_map:
                node = node_map[name]
            else:
                node = modulegraph.Node(name)
            node_map[name] = node
            return [node]

        graph = modulegraph.ModuleGraph()
        graph._safe_import_hook = _safe_import

        code = compile(textwrap.dedent('''\
            import sys
            import os.path

            def testfunc():
                import shutil
            '''), '<test>', 'exec', 0, False)
        graph.scan_code(code, mod)
        modules = [node.identifier for node in graph.nodes()]
        self.assertEqual(set(node_map), set(['sys', 'os.path', 'shutil']))


        # from module import a, b, c
        # from module import *
        #  both:
        #   -> with/without globals
        #   -> with/without modules in globals (e.g,
        #       from os import * adds dependency to os.path)
        # from .module import a
        # from ..module import a
        #   -> check levels
        # import name
        # import a.b
        #   -> should add dependency to a
        # try to build case where commented out
        # code would behave different than current code
        # (Carbon.SomeMod contains 'import Sibling' seems
        # to cause difference in real code)

        self.fail("actual test needed")



    @expectedFailure
    def test_load_package(self):
        self.fail("load_package")

    def test_find_module(self):
        record = []
        def mock_finder(name, path):
            record.append((name, path))
            return saved_finder(name, path)

        saved_finder = modulegraph.find_module
        try:
            modulegraph.find_module = mock_finder

            graph = modulegraph.ModuleGraph()
            m = graph._find_module('sys', None)
            self.assertEqual(record, [])
            self.assertEqual(m, (None, None, ("", "", imp.C_BUILTIN)))

            modulegraph.find_module = saved_finder
            xml = graph.import_hook("xml")[0]
            self.assertEqual(xml.identifier, 'xml')
            modulegraph.find_module = mock_finder

            self.assertRaises(ImportError, graph._find_module, 'xml', None)

            self.assertEqual(record, [])
            m = graph._find_module('shutil', None)
            self.assertEqual(record, [
                ('shutil', graph.path),
            ])
            self.assertTrue(isinstance(m, tuple))
            self.assertEqual(len(m), 3)
            self.assertTrue(hasattr(m[0], 'read'))
            self.assertIsInstance(m[0].read(), str)
            srcfn = shutil.__file__
            if srcfn.endswith('.pyc'):
                srcfn = srcfn[:-1]
            self.assertEqual(m[1], srcfn)
            self.assertEqual(m[2], ('.py', 'rU', imp.PY_SOURCE))
            m[0].close()

            m2 = graph._find_module('shutil', None)
            self.assertEqual(m[1:], m2[1:])
            m2[0].close()


            record[:] = []
            m = graph._find_module('sax', xml.packagepath, xml)
            self.assertEqual(m,
                    (None, os.path.join(os.path.dirname(xml.filename), 'sax'),
                    ('', '', imp.PKG_DIRECTORY)))
            self.assertEqual(record, [
                ('sax', xml.packagepath),
            ])
            if m[0] is not None: m[0].close()

        finally:
            modulegraph.find_module = saved_finder

    @expectedFailure
    def test_create_xref(self):
        self.fail("create_xref")

    @expectedFailure
    def test_itergraphreport(self):
        self.fail("itergraphreport")

    def test_report(self):
        graph = modulegraph.ModuleGraph()

        saved_stdout = sys.stdout
        try:
            fp = sys.stdout = StringIO()
            graph.report()
            lines = fp.getvalue().splitlines()
            fp.close()

            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0], '')
            self.assertEqual(lines[1], 'Class           Name                      File')
            self.assertEqual(lines[2], '-----           ----                      ----')

            fp = sys.stdout = StringIO()
            graph._safe_import_hook('os', None, ())
            graph._safe_import_hook('sys', None, ())
            graph._safe_import_hook('nomod', None, ())
            graph.report()
            lines = fp.getvalue().splitlines()
            fp.close()

            self.assertEqual(lines[0], '')
            self.assertEqual(lines[1], 'Class           Name                      File')
            self.assertEqual(lines[2], '-----           ----                      ----')
            expected = []
            for n in graph.flatten():
                if n.filename:
                    expected.append([type(n).__name__, n.identifier, n.filename])
                else:
                    expected.append([type(n).__name__, n.identifier])

            expected.sort()
            actual = [item.split() for item in lines[3:]]
            actual.sort()
            self.assertEqual(expected, actual)


        finally:
            sys.stdout = saved_stdout

    def test_graphreport(self):

        def my_iter(flatpackages="packages"):
            yield "line1\n"
            yield str(flatpackages) + "\n"
            yield "line2\n"

        graph = modulegraph.ModuleGraph()
        graph.itergraphreport = my_iter

        fp = StringIO()
        graph.graphreport(fp)
        self.assertEqual(fp.getvalue(), "line1\n()\nline2\n")

        fp = StringIO()
        graph.graphreport(fp, "deps")
        self.assertEqual(fp.getvalue(), "line1\ndeps\nline2\n")

        saved_stdout = sys.stdout
        try:
            sys.stdout = fp = StringIO()
            graph.graphreport()
            self.assertEqual(fp.getvalue(), "line1\n()\nline2\n")

        finally:
            sys.stdout = saved_stdout


    def test_replace_paths_in_code(self):
        graph = modulegraph.ModuleGraph(replace_paths=[
                ('path1', 'path2'),
                ('path3/path5', 'path4'),
            ])

        co = compile(textwrap.dedent("""
        [x for x in range(4)]
        """), "path4/index.py", 'exec', 0, 1)
        co = graph._replace_paths_in_code(co)
        self.assertEqual(co.co_filename, 'path4/index.py')

        co = compile(textwrap.dedent("""
        [x for x in range(4)]
        (x for x in range(4))
        """), "path1/index.py", 'exec', 0, 1)
        self.assertEqual(co.co_filename, 'path1/index.py')
        co = graph._replace_paths_in_code(co)
        self.assertEqual(co.co_filename, 'path2/index.py')
        for c in co.co_consts:
            if isinstance(c, type(co)):
                self.assertEqual(c.co_filename, 'path2/index.py')

        co = compile(textwrap.dedent("""
        [x for x in range(4)]
        """), "path3/path4/index.py", 'exec', 0, 1)
        co = graph._replace_paths_in_code(co)
        self.assertEqual(co.co_filename, 'path3/path4/index.py')

        co = compile(textwrap.dedent("""
        [x for x in range(4)]
        """), "path3/path5.py", 'exec', 0, 1)
        co = graph._replace_paths_in_code(co)
        self.assertEqual(co.co_filename, 'path3/path5.py')

        co = compile(textwrap.dedent("""
        [x for x in range(4)]
        """), "path3/path5/index.py", 'exec', 0, 1)
        co = graph._replace_paths_in_code(co)
        self.assertEqual(co.co_filename, 'path4/index.py')

    def test_createReference(self):
        graph = modulegraph.ModuleGraph()
        n1 = modulegraph.Node('n1')
        n2 = modulegraph.Node('n2')
        graph.addNode(n1)
        graph.addNode(n2)

        graph.createReference(n1, n2)
        outs, ins = map(list, graph.get_edges(n1))
        self.assertEqual(outs, [n2])
        self.assertEqual(ins, [])
        outs, ins = map(list, graph.get_edges(n2))
        self.assertEqual(outs, [])
        self.assertEqual(ins, [n1])

        e = graph.graph.edge_by_node('n1', 'n2')
        self.assertIsInstance(e, int)
        self.assertEqual(graph.graph.edge_data(e), 'direct')

    def test_create_xref(self):
        # XXX: This test is far from optimal, it just ensures
        # that all code is exercised to catch small bugs and
        # py3k issues without verifying that the code actually
        # works....
        graph = modulegraph.ModuleGraph()
        if __file__.endswith('.py'):
            graph.run_script(__file__)
        else:
            graph.run_script(__file__[:-1])

        graph.import_hook('os')
        graph.import_hook('xml.etree')
        graph.import_hook('unittest')

        fp = StringIO()
        graph.create_xref(out=fp)

        data = fp.getvalue()
        r = ET.fromstring(data)

    def test_itergraphreport(self):
        # XXX: This test is far from optimal, it just ensures
        # that all code is exercised to catch small bugs and
        # py3k issues without verifying that the code actually
        # works....
        graph = modulegraph.ModuleGraph()
        if __file__.endswith('.py'):
            graph.run_script(__file__)
        else:
            graph.run_script(__file__[:-1])
        graph.import_hook('os')
        graph.import_hook('xml.etree')
        graph.import_hook('unittest')
        graph.import_hook('distutils.command.build')

        fp = StringIO()
        list(graph.itergraphreport())

        # XXX: platpackages isn't implemented, and is undocumented hence
        # it is unclear what this is inteded to be...
        #list(graph.itergraphreport(flatpackages=...))




class CompatTests (unittest.TestCase):
    def test_Bchr(self):
        v = modulegraph._Bchr(ord('A'))
        if sys.version_info[0] == 2:
            self.assertTrue(isinstance(v, bytes))
            self.assertEqual(v, b'A')
        else:
            self.assertTrue(isinstance(v, int))
            self.assertEqual(v, ord('A'))

if __name__ == "__main__":
    unittest.main()
