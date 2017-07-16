"""
A helper module that can work with paths
that can refer to data inside a zipfile

XXX: Need to determine if isdir("zipfile.zip")
should return True or False. Currently returns
True, but that might do the wrong thing with
data-files that are zipfiles.
"""
import os as _os
import zipfile as _zipfile
import errno as _errno
import time as _time
import sys as _sys
import stat as _stat

_DFLT_DIR_MODE = (
      _stat.S_IFDIR
    | _stat.S_IXOTH
    | _stat.S_IXGRP
    | _stat.S_IXUSR
    | _stat.S_IROTH
    | _stat.S_IRGRP
    | _stat.S_IRUSR)

_DFLT_FILE_MODE = (
      _stat.S_IFREG
    | _stat.S_IROTH
    | _stat.S_IRGRP
    | _stat.S_IRUSR)


if _sys.version_info[0] == 2:
    from  StringIO import StringIO as _BaseStringIO
    from  StringIO import StringIO as _BaseBytesIO

    class _StringIO (_BaseStringIO):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()
            return False

    class _BytesIO (_BaseBytesIO):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()
            return False

else:
    from io import StringIO as _StringIO
    from io import BytesIO as _BytesIO




def _locate(path):
    full_path = path
    if _os.path.exists(path):
        return path, None

    else:
        rest = []
        root = _os.path.splitdrive(path)
        while path and path != root:
            path, bn = _os.path.split(path)
            rest.append(bn)
            if _os.path.exists(path):
                break

        if path == root:
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        if not _os.path.isfile(path):
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        rest.reverse()
        return path, '/'.join(rest).strip('/')

_open = open
def open(path, mode='r'):
    if 'w' in mode or 'a' in mode:
        raise IOError(
            _errno.EINVAL, path, "Write access not supported")
    elif 'r+' in mode:
        raise IOError(
            _errno.EINVAL, path, "Write access not supported")

    full_path = path
    path, rest = _locate(path)
    if not rest:
        return _open(path, mode)

    else:
        try:
            zf = _zipfile.ZipFile(path, 'r')

        except _zipfile.error:
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        try:
            data = zf.read(rest)
        except (_zipfile.error, KeyError):
            zf.close()
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")
        zf.close()

        if mode == 'rb':
            return _BytesIO(data)

        else:
            if _sys.version_info[0] == 3:
                data = data.decode('ascii')

            return _StringIO(data)

def listdir(path):
    full_path = path
    path, rest = _locate(path)
    if not rest and not _os.path.isfile(path):
        return _os.listdir(path)

    else:
        try:
            zf = _zipfile.ZipFile(path, 'r')

        except _zipfile.error:
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        result = set()
        seen = False
        try:
            for nm in zf.namelist():
                if rest is None:
                    seen = True
                    value = nm.split('/')[0]
                    if value:
                        result.add(value)

                elif nm.startswith(rest):
                    if nm == rest:
                        seen = True
                        value = ''
                        pass
                    elif nm[len(rest)] == '/':
                        seen = True
                        value = nm[len(rest)+1:].split('/')[0]
                    else:
                        value = None

                    if value:
                        result.add(value)
        except _zipfile.error:
            zf.close()
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        zf.close()

        if not seen:
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        return list(result)

def isfile(path):
    full_path = path
    path, rest = _locate(path)
    if not rest:
        ok =  _os.path.isfile(path)
        if ok:
            try:
                zf = _zipfile.ZipFile(path, 'r')
                return False
            except (_zipfile.error, IOError):
                return True
        return False

    zf = None
    try:
        zf = _zipfile.ZipFile(path, 'r')
        info = zf.getinfo(rest)
        zf.close()
        return True
    except (KeyError, _zipfile.error):
        if zf is not None:
            zf.close()

        # Check if this is a directory
        try:
            info = zf.getinfo(rest + '/')
        except KeyError:
            pass
        else:
            return False

        rest = rest + '/'
        for nm in zf.namelist():
            if nm.startswith(rest):
                # Directory
                return False

        # No trace in zipfile
        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")




def isdir(path):
    full_path = path
    path, rest = _locate(path)
    if not rest:
        ok =  _os.path.isdir(path)
        if not ok:
            try:
                zf = _zipfile.ZipFile(path, 'r')
            except (_zipfile.error, IOError):
                return False
            return True
        return True

    zf = None
    try:
        try:
            zf = _zipfile.ZipFile(path)
        except _zipfile.error:
            raise IOError(
                _errno.ENOENT, full_path,
                "No such file or directory")

        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass
        else:
            # File found
            return False

        rest = rest + '/'
        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass
        else:
            # Directory entry found
            return True

        for nm in zf.namelist():
            if nm.startswith(rest):
                return True

        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")
    finally:
        if zf is not None:
            zf.close()


def islink(path):
    full_path = path
    path, rest = _locate(path)
    if not rest:
        return _os.path.islink(path)

    try:
        zf = _zipfile.ZipFile(path)
    except _zipfile.error:
        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")
    try:


        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass
        else:
            # File
            return False

        rest += '/'
        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass
        else:
            # Directory
            return False

        for nm in zf.namelist():
            if nm.startswith(rest):
                # Directory without listing
                return False

        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")

    finally:
        zf.close()


def readlink(path):
    full_path = path
    path, rest = _locate(path)
    if rest:
        # No symlinks inside zipfiles
        raise OSError(
            _errno.ENOENT, full_path,
            "No such file or directory")

    return _os.readlink(path)

def getmode(path):
    full_path = path
    path, rest = _locate(path)
    if not rest:
        return _os.stat(path).st_mode

    zf = None
    try:
        zf = _zipfile.ZipFile(path)
        info = None

        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass

        if info is None:
            try:
                info = zf.getinfo(rest + '/')
            except KeyError:
                pass

        if info is None:
            rest = rest + '/'
            for nm in zf.namelist():
                if nm.startswith(rest):
                    break
            else:
                raise IOError(
                    _errno.ENOENT, full_path,
                    "No such file or directory")

            # Directory exists, but has no entry of its own.
            return _DFLT_DIR_MODE

        # The mode is stored without file-type in external_attr.
        if (info.external_attr >> 16) != 0:
            return _stat.S_IFREG | (info.external_attr >> 16)
        else:
            return _DFLT_FILE_MODE


    except KeyError:
        if zf is not None:
            zf.close()
        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")

def getmtime(path):
    full_path = path
    path, rest = _locate(path)
    if not rest:
        return _os.path.getmtime(path)

    zf = None
    try:
        zf = _zipfile.ZipFile(path)
        info = None

        try:
            info = zf.getinfo(rest)
        except KeyError:
            pass

        if info is None:
            try:
                info = zf.getinfo(rest + '/')
            except KeyError:
                pass

        if info is None:
            rest = rest + '/'
            for nm in zf.namelist():
                if nm.startswith(rest):
                    break
            else:
                raise IOError(
                    _errno.ENOENT, full_path,
                    "No such file or directory")

            # Directory exists, but has no entry of its
            # own, fake mtime by using the timestamp of
            # the zipfile itself.
            return _os.path.getmtime(path)

        return _time.mktime(info.date_time + (0, 0, -1))

    except KeyError:
        if zf is not None:
            zf.close()
        raise IOError(
            _errno.ENOENT, full_path,
            "No such file or directory")
