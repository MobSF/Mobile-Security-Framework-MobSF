"""
modulegraph.find_modules - High-level module dependency finding interface
=========================================================================

History
........

Originally (loosely) based on code in py2exe's build_exe.py by Thomas Heller.
"""
from __future__ import absolute_import

import sys
import os
import imp
import warnings

import modulegraph.modulegraph as modulegraph
from modulegraph.modulegraph import Alias, Script, Extension
from modulegraph.util import imp_find_module

__all__ = [
    'find_modules', 'parse_mf_results'
]

def get_implies():
    result = {
        # imports done from builtin modules in C code (untrackable by modulegraph)
        "_curses":      ["curses"],
        "posix":        ["resource"],
        "gc":           ["time"],
        "time":         ["_strptime"],
        "datetime":     ["time"],
        "MacOS":        ["macresource"],
        "cPickle":      ["copy_reg", "cStringIO"],
        "parser":       ["copy_reg"],
        "codecs":       ["encodings"],
        "cStringIO":    ["copy_reg"],
        "_sre":         ["copy", "string", "sre"],
        "zipimport":    ["zlib"],

        # Python 3.2:
        "_datetime":    ["time", "_strptime"],
        "_json":        ["json.decoder"],
        "_pickle":      ["codecs", "copyreg", "_compat_pickle"],
        "_posixsubprocess": ["gc"],
        "_ssl":         ["socket"],

        # Python 3.3:
        "_elementtree": ["copy", "xml.etree.ElementPath" ],

        # mactoolboxglue can do a bunch more of these
        # that are far harder to predict, these should be tracked
        # manually for now.

        # this isn't C, but it uses __import__
        "anydbm":       ["dbhash", "gdbm", "dbm", "dumbdbm", "whichdb"],
        # package aliases
        "wxPython.wx":  Alias('wx'),

    }

    if sys.version_info[0] == 3:
        result["_sre"] = ["copy", "re"]
        result["parser"] = ["copyreg"]

        # _frozen_importlib is part of the interpreter itself
        result["_frozen_importlib"] = None

    if sys.version_info[0] == 2 and sys.version_info[1] >= 5:
        result.update({
            "email.base64MIME":         Alias("email.base64mime"),
            "email.Charset":            Alias("email.charset"),
            "email.Encoders":           Alias("email.encoders"),
            "email.Errors":             Alias("email.errors"),
            "email.Feedparser":         Alias("email.feedParser"),
            "email.Generator":          Alias("email.generator"),
            "email.Header":             Alias("email.header"),
            "email.Iterators":          Alias("email.iterators"),
            "email.Message":            Alias("email.message"),
            "email.Parser":             Alias("email.parser"),
            "email.quopriMIME":         Alias("email.quoprimime"),
            "email.Utils":              Alias("email.utils"),
            "email.MIMEAudio":          Alias("email.mime.audio"),
            "email.MIMEBase":           Alias("email.mime.base"),
            "email.MIMEImage":          Alias("email.mime.image"),
            "email.MIMEMessage":        Alias("email.mime.message"),
            "email.MIMEMultipart":      Alias("email.mime.multipart"),
            "email.MIMENonMultipart":   Alias("email.mime.nonmultipart"),
            "email.MIMEText":           Alias("email.mime.text"),
        })

    if sys.version_info[:2] >= (2, 5):
        result["_elementtree"] = ["pyexpat"]

        import xml.etree
        files = os.listdir(xml.etree.__path__[0])
        for fn in files:
            if fn.endswith('.py') and fn != "__init__.py":
                result["_elementtree"].append("xml.etree.%s"%(fn[:-3],))

    if sys.version_info[:2] >= (2, 6):
        result['future_builtins'] = ['itertools']

    # os.path is an alias for a platform specific submodule,
    # ensure that the graph shows this.
    result['os.path'] = Alias(os.path.__name__)


    return result

def parse_mf_results(mf):
    """
    Return two lists: the first one contains the python files in the graph,
    the second the C extensions.

    :param mf: a :class:`modulegraph.modulegraph.ModuleGraph` instance
    """
    #for name, imports in get_hidden_imports().items():
    #    if name in mf.modules.keys():
    #        for mod in imports:
    #            mf.import_hook(mod)

    # Retrieve modules from modulegraph
    py_files = []
    extensions = []

    for item in mf.flatten():
        # There may be __main__ modules (from mf.run_script), but
        # we don't need it in the zipfile we build.
        if item.identifier == "__main__":
            continue
        src = item.filename
        if src and src != '-':
            if isinstance(item, Script):
                # Scripts are python files
                py_files.append(item)

            elif isinstance(item, Extension):
                extensions.append(item)

            else:
                py_files.append(item)

    # sort on the file names, the output is nicer to read
    py_files.sort(key=lambda v: v.filename)
    extensions.sort(key=lambda v: v.filename)
    return py_files, extensions


def plat_prepare(includes, packages, excludes):
    # used by Python itself
    includes.update(["warnings", "unicodedata", "weakref"])

    #if os.uname()[0] != 'java':
        # Jython specific imports in the stdlib:
        #excludes.update([
        #    'java.lang',
        #    'org.python.core',
        #])

    if not sys.platform.startswith('irix'):
        excludes.update([
            'AL',
            'sgi',
            'vms_lib',
        ])

    if not sys.platform in ('mac', 'darwin'):
        # XXX - this doesn't look nearly complete
        excludes.update([
            'Audio_mac',
            'Carbon.File',
            'Carbon.Folder',
            'Carbon.Folders',
            'EasyDialogs',
            'MacOS',
            'macfs',
            'macostools',
            #'macpath',
            '_scproxy',
        ])

    if not sys.platform == 'win32':
        # only win32
        excludes.update([
            #'ntpath',
            'nturl2path',
            'win32api',
            'win32con',
            'win32event',
            'win32evtlogutil',
            'win32evtlog',
            'win32file',
            'win32gui',
            'win32pipe',
            'win32process',
            'win32security',
            'pywintypes',
            'winsound',
            'win32',
            '_winreg',
            '_winapi',
            'msvcrt',
            'winreg',
            '_subprocess',
         ])

    if not sys.platform == 'riscos':
        excludes.update([
             'riscosenviron',
             #'riscospath',
             'rourl2path',
          ])

    if not sys.platform == 'dos' or sys.platform.startswith('ms-dos'):
        excludes.update([
            'dos',
        ])

    if not sys.platform == 'os2emx':
        excludes.update([
            #'os2emxpath',
            '_emx_link',
        ])

    excludes.update(set(['posix', 'nt', 'os2', 'mac', 'ce', 'riscos']) - set(sys.builtin_module_names))

    # Carbon.Res depends on this, but the module hasn't been present
    # for a while...
    excludes.add('OverrideFrom23')
    excludes.add('OverrideFrom23._Res')

    # import trickery in the dummy_threading module (stdlib)
    excludes.add('_dummy_threading')

    try:
        imp_find_module('poll')
    except ImportError:
        excludes.update([
            'poll',
        ])

def find_needed_modules(mf=None, scripts=(), includes=(), packages=(), warn=warnings.warn):
    if mf is None:
        mf = modulegraph.ModuleGraph()
    # feed Modulefinder with everything, and return it.

    for path in scripts:
        mf.run_script(path)

    for mod in includes:
        try:
            if mod[-2:] == '.*':
                mf.import_hook(mod[:-2], None, ['*'])
            else:
                mf.import_hook(mod)
        except ImportError:
            warn("No module named %s"%(mod,))

    for f in packages:
        # If modulegraph has seen a reference to the package, then
        # we prefer to believe that (imp_find_module doesn't seem to locate
        # sub-packages)
        m = mf.findNode(f)
        if m is not None:
            path = m.packagepath[0]
        else:
            # Find path of package
            # TODO: use imp_find_module_or_importer
            try:
                path = imp_find_module(f, mf.path)[1]
            except ImportError:
                warn("No package named %s" % f)
                continue

        # walk the path to find subdirs containing __init__.py files
        # scan the results (directory of __init__.py files)
        # first trim the path (of the head package),
        # then convert directory name in package name,
        # finally push into modulegraph.
        # FIXME:
        # 1) Needs to be adjusted for namespace packages in python 3.3
        # 2) Code is fairly dodgy and needs better tests
        for (dirpath, dirnames, filenames) in os.walk(path):
            if '__init__.py' in filenames and dirpath.startswith(path):
                package = f + '.' + dirpath[len(path)+1:].replace(os.sep, '.')
                if package.endswith('.'):
                    package = package[:-1]
                m = mf.import_hook(package, None, ["*"])
            else:
                # Exclude subtrees that aren't packages
                dirnames[:] = []


    return mf

#
# resource constants
#
PY_SUFFIXES = ['.py', '.pyw', '.pyo', '.pyc']
C_SUFFIXES = [
    _triple[0] for _triple in imp.get_suffixes()
    if _triple[2] == imp.C_EXTENSION
]

#
# side-effects
#

def _replacePackages():
    REPLACEPACKAGES = {
        '_xmlplus':     'xml',
    }
    for k,v in REPLACEPACKAGES.items():
        modulegraph.replacePackage(k, v)

_replacePackages()

def find_modules(scripts=(), includes=(), packages=(), excludes=(), path=None, debug=0):
    """
    High-level interface, takes iterables for:
        scripts, includes, packages, excludes

    And returns a :class:`modulegraph.modulegraph.ModuleGraph` instance,
    python_files, and extensions

    python_files is a list of pure python dependencies as modulegraph.Module objects,
    extensions is a list of platform-specific C extension dependencies as modulegraph.Module objects
    """
    scripts = set(scripts)
    includes = set(includes)
    packages = set(packages)
    excludes = set(excludes)
    plat_prepare(includes, packages, excludes)
    mf = modulegraph.ModuleGraph(
        path=path,
        excludes=(excludes - includes),
        implies=get_implies(),
        debug=debug,
    )
    find_needed_modules(mf, scripts, includes, packages)
    return mf

def test():
    if '-g' in sys.argv[1:]:
        sys.argv.remove('-g')
        dograph = True
    else:
        dograph = False
    if '-x' in sys.argv[1:]:
        sys.argv.remove('-x')
        doxref = True
    else:
        doxref= False

    scripts = sys.argv[1:] or [__file__]
    mf = find_modules(scripts=scripts)
    if doxref:
        mf.create_xref()
    elif dograph:
        mf.graphreport()
    else:
        mf.report()

if __name__ == '__main__':
    test()
