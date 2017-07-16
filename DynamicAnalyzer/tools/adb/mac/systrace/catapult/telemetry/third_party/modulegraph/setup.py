"""
Shared setup file for simple python packages. Uses a setup.cfg that
is the same as the distutils2 project, unless noted otherwise.

It exists for two reasons:
1) This makes it easier to reuse setup.py code between my own
   projects

2) Easier migration to distutils2 when that catches on.

Additional functionality:

* Section metadata:
    requires-test:  Same as 'tests_require' option for setuptools.

"""

import sys
import os
import re
import platform
from fnmatch import fnmatch
import os
import sys
import time
import tempfile
import tarfile
try:
    import urllib.request as urllib
except ImportError:
    import urllib
from distutils import log
try:
    from hashlib import md5

except ImportError:
    from md5 import md5

if sys.version_info[0] == 2:
    from ConfigParser import RawConfigParser, NoOptionError, NoSectionError
else:
    from configparser import RawConfigParser, NoOptionError, NoSectionError

ROOTDIR = os.path.dirname(os.path.abspath(__file__))


#
#
#
# Parsing the setup.cfg and converting it to something that can be
# used by setuptools.setup()
#
#
#

def eval_marker(value):
    """
    Evaluate an distutils2 environment marker.

    This code is unsafe when used with hostile setup.cfg files,
    but that's not a problem for our own files.
    """
    value = value.strip()

    class M:
        def __init__(self, **kwds):
            for k, v in kwds.items():
                setattr(self, k, v)

    variables = {
        'python_version': '%d.%d'%(sys.version_info[0], sys.version_info[1]),
        'python_full_version': sys.version.split()[0],
        'os': M(
            name=os.name,
        ),
        'sys': M(
            platform=sys.platform,
        ),
        'platform': M(
            version=platform.version(),
            machine=platform.machine(),
        ),
    }

    return bool(eval(value, variables, variables))


    return True

def _opt_value(cfg, into, section, key, transform = None):
    try:
        v = cfg.get(section, key)
        if transform != _as_lines and ';' in v:
            v, marker = v.rsplit(';', 1)
            if not eval_marker(marker):
                return

            v = v.strip()

        if v:
            if transform:
                into[key] = transform(v.strip())
            else:
                into[key] = v.strip()

    except (NoOptionError, NoSectionError):
        pass

def _as_bool(value):
    if value.lower() in ('y', 'yes', 'on'):
        return True
    elif value.lower() in ('n', 'no', 'off'):
        return False
    elif value.isdigit():
        return bool(int(value))
    else:
        raise ValueError(value)

def _as_list(value):
    return value.split()

def _as_lines(value):
    result = []
    for v in value.splitlines():
        if ';' in v:
            v, marker = v.rsplit(';', 1)
            if not eval_marker(marker):
                continue

            v = v.strip()
            if v:
                result.append(v)
        else:
            result.append(v)
    return result

def _map_requirement(value):
    m = re.search(r'(\S+)\s*(?:\((.*)\))?', value)
    name = m.group(1)
    version = m.group(2)

    if version is None:
        return name

    else:
        mapped = []
        for v in version.split(','):
            v = v.strip()
            if v[0].isdigit():
                # Checks for a specific version prefix
                m = v.rsplit('.', 1)
                mapped.append('>=%s,<%s.%s'%(
                    v, m[0], int(m[1])+1))

            else:
                mapped.append(v)
        return '%s %s'%(name, ','.join(mapped),)

def _as_requires(value):
    requires = []
    for req in value.splitlines():
        if ';' in req:
            req, marker = v.rsplit(';', 1)
            if not eval_marker(marker):
                continue
            req = req.strip()

        if not req:
            continue
        requires.append(_map_requirement(req))
    return requires

def parse_setup_cfg():
    cfg = RawConfigParser()
    r = cfg.read([os.path.join(ROOTDIR, 'setup.cfg')])
    if len(r) != 1:
        print("Cannot read 'setup.cfg'")
        sys.exit(1)

    metadata = dict(
            name        = cfg.get('metadata', 'name'),
            version     = cfg.get('metadata', 'version'),
            description = cfg.get('metadata', 'description'),
    )

    _opt_value(cfg, metadata, 'metadata', 'license')
    _opt_value(cfg, metadata, 'metadata', 'maintainer')
    _opt_value(cfg, metadata, 'metadata', 'maintainer_email')
    _opt_value(cfg, metadata, 'metadata', 'author')
    _opt_value(cfg, metadata, 'metadata', 'author_email')
    _opt_value(cfg, metadata, 'metadata', 'url')
    _opt_value(cfg, metadata, 'metadata', 'download_url')
    _opt_value(cfg, metadata, 'metadata', 'classifiers', _as_lines)
    _opt_value(cfg, metadata, 'metadata', 'platforms', _as_list)
    _opt_value(cfg, metadata, 'metadata', 'packages', _as_list)
    _opt_value(cfg, metadata, 'metadata', 'keywords', _as_list)

    try:
        v = cfg.get('metadata', 'requires-dist')

    except (NoOptionError, NoSectionError):
        pass

    else:
        requires = _as_requires(v)
        if requires:
            metadata['install_requires'] = requires

    try:
        v = cfg.get('metadata', 'requires-test')

    except (NoOptionError, NoSectionError):
        pass

    else:
        requires = _as_requires(v)
        if requires:
            metadata['tests_require'] = requires


    try:
        v = cfg.get('metadata', 'long_description_file')
    except (NoOptionError, NoSectionError):
        pass

    else:
        parts = []
        for nm in v.split():
            fp = open(nm, 'rU')
            parts.append(fp.read())
            fp.close()

        metadata['long_description'] = '\n\n'.join(parts)


    try:
        v = cfg.get('metadata', 'zip-safe')
    except (NoOptionError, NoSectionError):
        pass

    else:
        metadata['zip_safe'] = _as_bool(v)

    try:
        v = cfg.get('metadata', 'console_scripts')
    except (NoOptionError, NoSectionError):
        pass

    else:
        if 'entry_points' not in metadata:
            metadata['entry_points'] = {}

        metadata['entry_points']['console_scripts'] = v.splitlines()

    if sys.version_info[:2] <= (2,6):
        try:
            metadata['tests_require'] += ", unittest2"
        except KeyError:
            metadata['tests_require'] = "unittest2"

    return metadata


#
#
#
# Bootstrapping setuptools/distribute, based on
# a heavily modified version of distribute_setup.py
#
#
#


SETUPTOOLS_PACKAGE='setuptools'


try:
    import subprocess

    def _python_cmd(*args):
        args = (sys.executable,) + args
        return subprocess.call(args) == 0

except ImportError:
    def _python_cmd(*args):
        args = (sys.executable,) + args
        new_args = []
        for a in args:
            new_args.append(a.replace("'", "'\"'\"'"))
        os.system(' '.join(new_args)) == 0


try:
    import json

    def get_pypi_src_download(package):
        url = 'https://pypi.python.org/pypi/%s/json'%(package,)
        fp = urllib.urlopen(url)
        try:
            try:
                data = fp.read()

            finally:
                fp.close()
        except urllib.error:
            raise RuntimeError("Cannot determine download link for %s"%(package,))

        pkgdata = json.loads(data.decode('utf-8'))
        if 'urls' not in pkgdata:
            raise RuntimeError("Cannot determine download link for %s"%(package,))

        for info in pkgdata['urls']:
            if info['packagetype'] == 'sdist' and info['url'].endswith('tar.gz'):
                return (info.get('md5_digest'), info['url'])

        raise RuntimeError("Cannot determine downlink link for %s"%(package,))

except ImportError:
    # Python 2.5 compatibility, no JSON in stdlib but luckily JSON syntax is
    # simular enough to Python's syntax to be able to abuse the Python compiler

    import _ast as ast

    def get_pypi_src_download(package):
        url = 'https://pypi.python.org/pypi/%s/json'%(package,)
        fp = urllib.urlopen(url)
        try:
            try:
                data = fp.read()

            finally:
                fp.close()
        except urllib.error:
            raise RuntimeError("Cannot determine download link for %s"%(package,))


        a = compile(data, '-', 'eval', ast.PyCF_ONLY_AST)
        if not isinstance(a, ast.Expression):
            raise RuntimeError("Cannot determine download link for %s"%(package,))

        a = a.body
        if not isinstance(a, ast.Dict):
            raise RuntimeError("Cannot determine download link for %s"%(package,))

        for k, v in zip(a.keys, a.values):
            if not isinstance(k, ast.Str):
                raise RuntimeError("Cannot determine download link for %s"%(package,))

            k = k.s
            if k == 'urls':
                a = v
                break
        else:
            raise RuntimeError("PyPI JSON for %s doesn't contain URLs section"%(package,))

        if not isinstance(a, ast.List):
            raise RuntimeError("Cannot determine download link for %s"%(package,))

        for info in v.elts:
            if not isinstance(info, ast.Dict):
                raise RuntimeError("Cannot determine download link for %s"%(package,))
            url = None
            packagetype = None
            chksum = None

            for k, v in zip(info.keys, info.values):
                if not isinstance(k, ast.Str):
                    raise RuntimeError("Cannot determine download link for %s"%(package,))

                if k.s == 'url':
                    if not isinstance(v, ast.Str):
                        raise RuntimeError("Cannot determine download link for %s"%(package,))
                    url = v.s

                elif k.s == 'packagetype':
                    if not isinstance(v, ast.Str):
                        raise RuntimeError("Cannot determine download link for %s"%(package,))
                    packagetype = v.s

                elif k.s == 'md5_digest':
                    if not isinstance(v, ast.Str):
                        raise RuntimeError("Cannot determine download link for %s"%(package,))
                    chksum = v.s

            if url is not None and packagetype == 'sdist' and url.endswith('.tar.gz'):
                return (chksum, url)

        raise RuntimeError("Cannot determine download link for %s"%(package,))

def _build_egg(egg, tarball, to_dir):
    # extracting the tarball
    tmpdir = tempfile.mkdtemp()
    log.warn('Extracting in %s', tmpdir)
    old_wd = os.getcwd()
    try:
        os.chdir(tmpdir)
        tar = tarfile.open(tarball)
        _extractall(tar)
        tar.close()

        # going in the directory
        subdir = os.path.join(tmpdir, os.listdir(tmpdir)[0])
        os.chdir(subdir)
        log.warn('Now working in %s', subdir)

        # building an egg
        log.warn('Building a %s egg in %s', egg, to_dir)
        _python_cmd('setup.py', '-q', 'bdist_egg', '--dist-dir', to_dir)

    finally:
        os.chdir(old_wd)
    # returning the result
    log.warn(egg)
    if not os.path.exists(egg):
        raise IOError('Could not build the egg.')


def _do_download(to_dir, packagename=SETUPTOOLS_PACKAGE):
    tarball = download_setuptools(packagename, to_dir)
    version = tarball.split('-')[-1][:-7]
    egg = os.path.join(to_dir, '%s-%s-py%d.%d.egg'
                       % (packagename, version, sys.version_info[0], sys.version_info[1]))
    if not os.path.exists(egg):
        _build_egg(egg, tarball, to_dir)
    sys.path.insert(0, egg)
    import setuptools
    setuptools.bootstrap_install_from = egg


def use_setuptools():
    # making sure we use the absolute path
    return _do_download(os.path.abspath(os.curdir))

def download_setuptools(packagename, to_dir):
    # making sure we use the absolute path
    to_dir = os.path.abspath(to_dir)
    try:
        from urllib.request import urlopen
    except ImportError:
        from urllib2 import urlopen

    chksum, url = get_pypi_src_download(packagename)
    tgz_name = os.path.basename(url)
    saveto = os.path.join(to_dir, tgz_name)

    src = dst = None
    if not os.path.exists(saveto):  # Avoid repeated downloads
        try:
            log.warn("Downloading %s", url)
            src = urlopen(url)
            # Read/write all in one block, so we don't create a corrupt file
            # if the download is interrupted.
            data = src.read()

            if chksum is not None:
                data_sum = md5(data).hexdigest()
                if data_sum != chksum:
                    raise RuntimeError("Downloading %s failed: corrupt checksum"%(url,))


            dst = open(saveto, "wb")
            dst.write(data)
        finally:
            if src:
                src.close()
            if dst:
                dst.close()
    return os.path.realpath(saveto)



def _extractall(self, path=".", members=None):
    """Extract all members from the archive to the current working
       directory and set owner, modification time and permissions on
       directories afterwards. `path' specifies a different directory
       to extract to. `members' is optional and must be a subset of the
       list returned by getmembers().
    """
    import copy
    import operator
    from tarfile import ExtractError
    directories = []

    if members is None:
        members = self

    for tarinfo in members:
        if tarinfo.isdir():
            # Extract directories with a safe mode.
            directories.append(tarinfo)
            tarinfo = copy.copy(tarinfo)
            tarinfo.mode = 448 # decimal for oct 0700
        self.extract(tarinfo, path)

    # Reverse sort directories.
    if sys.version_info < (2, 4):
        def sorter(dir1, dir2):
            return cmp(dir1.name, dir2.name)
        directories.sort(sorter)
        directories.reverse()
    else:
        directories.sort(key=operator.attrgetter('name'), reverse=True)

    # Set correct owner, mtime and filemode on directories.
    for tarinfo in directories:
        dirpath = os.path.join(path, tarinfo.name)
        try:
            self.chown(tarinfo, dirpath)
            self.utime(tarinfo, dirpath)
            self.chmod(tarinfo, dirpath)
        except ExtractError:
            e = sys.exc_info()[1]
            if self.errorlevel > 1:
                raise
            else:
                self._dbg(1, "tarfile: %s" % e)


#
#
#
# Definitions of custom commands
#
#
#

try:
    import setuptools

except ImportError:
    use_setuptools()

from setuptools import setup

try:
    from distutils.core import PyPIRCCommand
except ImportError:
    PyPIRCCommand = None # Ancient python version

from distutils.core import Command
from distutils.errors  import DistutilsError
from distutils import log

if PyPIRCCommand is None:
    class upload_docs (Command):
        description = "upload sphinx documentation"
        user_options = []

        def initialize_options(self):
            pass

        def finalize_options(self):
            pass

        def run(self):
            raise DistutilsError("not supported on this version of python")

else:
    class upload_docs (PyPIRCCommand):
        description = "upload sphinx documentation"
        user_options = PyPIRCCommand.user_options

        def initialize_options(self):
            PyPIRCCommand.initialize_options(self)
            self.username = ''
            self.password = ''


        def finalize_options(self):
            PyPIRCCommand.finalize_options(self)
            config = self._read_pypirc()
            if config != {}:
                self.username = config['username']
                self.password = config['password']


        def run(self):
            import subprocess
            import shutil
            import zipfile
            import os
            import urllib
            import StringIO
            from base64 import standard_b64encode
            import httplib
            import urlparse

            # Extract the package name from distutils metadata
            meta = self.distribution.metadata
            name = meta.get_name()

            # Run sphinx
            if os.path.exists('doc/_build'):
                shutil.rmtree('doc/_build')
            os.mkdir('doc/_build')

            p = subprocess.Popen(['make', 'html'],
                cwd='doc')
            exit = p.wait()
            if exit != 0:
                raise DistutilsError("sphinx-build failed")

            # Collect sphinx output
            if not os.path.exists('dist'):
                os.mkdir('dist')
            zf = zipfile.ZipFile('dist/%s-docs.zip'%(name,), 'w',
                    compression=zipfile.ZIP_DEFLATED)

            for toplevel, dirs, files in os.walk('doc/_build/html'):
                for fn in files:
                    fullname = os.path.join(toplevel, fn)
                    relname = os.path.relpath(fullname, 'doc/_build/html')

                    print ("%s -> %s"%(fullname, relname))

                    zf.write(fullname, relname)

            zf.close()

            # Upload the results, this code is based on the distutils
            # 'upload' command.
            content = open('dist/%s-docs.zip'%(name,), 'rb').read()

            data = {
                ':action': 'doc_upload',
                'name': name,
                'content': ('%s-docs.zip'%(name,), content),
            }
            auth = "Basic " + standard_b64encode(self.username + ":" +
                 self.password)


            boundary = '--------------GHSKFJDLGDS7543FJKLFHRE75642756743254'
            sep_boundary = '\n--' + boundary
            end_boundary = sep_boundary + '--'
            body = StringIO.StringIO()
            for key, value in data.items():
                if not isinstance(value, list):
                    value = [value]

                for value in value:
                    if isinstance(value, tuple):
                        fn = ';filename="%s"'%(value[0])
                        value = value[1]
                    else:
                        fn = ''

                    body.write(sep_boundary)
                    body.write('\nContent-Disposition: form-data; name="%s"'%key)
                    body.write(fn)
                    body.write("\n\n")
                    body.write(value)

            body.write(end_boundary)
            body.write('\n')
            body = body.getvalue()

            self.announce("Uploading documentation to %s"%(self.repository,), log.INFO)

            schema, netloc, url, params, query, fragments = \
                    urlparse.urlparse(self.repository)


            if schema == 'http':
                http = httplib.HTTPConnection(netloc)
            elif schema == 'https':
                http = httplib.HTTPSConnection(netloc)
            else:
                raise AssertionError("unsupported schema "+schema)

            data = ''
            loglevel = log.INFO
            try:
                http.connect()
                http.putrequest("POST", url)
                http.putheader('Content-type',
                    'multipart/form-data; boundary=%s'%boundary)
                http.putheader('Content-length', str(len(body)))
                http.putheader('Authorization', auth)
                http.endheaders()
                http.send(body)
            except socket.error:
                e = socket.exc_info()[1]
                self.announce(str(e), log.ERROR)
                return

            r = http.getresponse()
            if r.status in (200, 301):
                self.announce('Upload succeeded (%s): %s' % (r.status, r.reason),
                    log.INFO)
            else:
                self.announce('Upload failed (%s): %s' % (r.status, r.reason),
                    log.ERROR)

                print ('-'*75)
                print (r.read())
                print ('-'*75)


def recursiveGlob(root, pathPattern):
    """
    Recursively look for files matching 'pathPattern'. Return a list
    of matching files/directories.
    """
    result = []

    for rootpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fnmatch(fn, pathPattern):
                result.append(os.path.join(rootpath, fn))
    return result


def importExternalTestCases(unittest,
        pathPattern="test_*.py", root=".", package=None):
    """
    Import all unittests in the PyObjC tree starting at 'root'
    """

    testFiles = recursiveGlob(root, pathPattern)
    testModules = map(lambda x:x[len(root)+1:-3].replace('/', '.'), testFiles)
    if package is not None:
        testModules = [(package + '.' + m) for m in testModules]

    suites = []

    for modName in testModules:
        try:
            module = __import__(modName)
        except ImportError:
            print("SKIP %s: %s"%(modName, sys.exc_info()[1]))
            continue

        if '.' in modName:
            for elem in modName.split('.')[1:]:
                module = getattr(module, elem)

        s = unittest.defaultTestLoader.loadTestsFromModule(module)
        suites.append(s)

    return unittest.TestSuite(suites)



class test (Command):
    description = "run test suite"
    user_options = [
        ('verbosity=', None, "print what tests are run"),
    ]

    def initialize_options(self):
        self.verbosity='1'

    def finalize_options(self):
        if isinstance(self.verbosity, str):
            self.verbosity = int(self.verbosity)


    def cleanup_environment(self):
        ei_cmd = self.get_finalized_command('egg_info')
        egg_name = ei_cmd.egg_name.replace('-', '_')

        to_remove =  []
        for dirname in sys.path:
            bn = os.path.basename(dirname)
            if bn.startswith(egg_name + "-"):
                to_remove.append(dirname)

        for dirname in to_remove:
            log.info("removing installed %r from sys.path before testing"%(
                dirname,))
            sys.path.remove(dirname)

    def add_project_to_sys_path(self):
        from pkg_resources import normalize_path, add_activation_listener
        from pkg_resources import working_set, require

        self.reinitialize_command('egg_info')
        self.run_command('egg_info')
        self.reinitialize_command('build_ext', inplace=1)
        self.run_command('build_ext')


        # Check if this distribution is already on sys.path
        # and remove that version, this ensures that the right
        # copy of the package gets tested.

        self.__old_path = sys.path[:]
        self.__old_modules = sys.modules.copy()


        ei_cmd = self.get_finalized_command('egg_info')
        sys.path.insert(0, normalize_path(ei_cmd.egg_base))
        sys.path.insert(1, os.path.dirname(__file__))

        # Strip the namespace packages defined in this distribution
        # from sys.modules, needed to reset the search path for
        # those modules.

        nspkgs = getattr(self.distribution, 'namespace_packages')
        if nspkgs is not None:
            for nm in nspkgs:
                del sys.modules[nm]

        # Reset pkg_resources state:
        add_activation_listener(lambda dist: dist.activate())
        working_set.__init__()
        require('%s==%s'%(ei_cmd.egg_name, ei_cmd.egg_version))

    def remove_from_sys_path(self):
        from pkg_resources import working_set
        sys.path[:] = self.__old_path
        sys.modules.clear()
        sys.modules.update(self.__old_modules)
        working_set.__init__()


    def run(self):
        import unittest

        # Ensure that build directory is on sys.path (py3k)

        self.cleanup_environment()
        self.add_project_to_sys_path()

        try:
            meta = self.distribution.metadata
            name = meta.get_name()
            test_pkg = name + "_tests"
            suite = importExternalTestCases(unittest,
                    "test_*.py", test_pkg, test_pkg)

            runner = unittest.TextTestRunner(verbosity=self.verbosity)
            result = runner.run(suite)

            # Print out summary. This is a structured format that
            # should make it easy to use this information in scripts.
            summary = dict(
                count=result.testsRun,
                fails=len(result.failures),
                errors=len(result.errors),
                xfails=len(getattr(result, 'expectedFailures', [])),
                xpass=len(getattr(result, 'expectedSuccesses', [])),
                skip=len(getattr(result, 'skipped', [])),
            )
            print("SUMMARY: %s"%(summary,))

        finally:
            self.remove_from_sys_path()

#
#
#
#  And finally run the setuptools main entry point.
#
#
#

metadata = parse_setup_cfg()

setup(
    cmdclass=dict(
        upload_docs=upload_docs,
        test=test,
    ),
    **metadata
)
