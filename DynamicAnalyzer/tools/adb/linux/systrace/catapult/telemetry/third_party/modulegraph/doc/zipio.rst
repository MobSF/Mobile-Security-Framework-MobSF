:mod:`modulegraph.zipio` --- Read-only filesystem access
========================================================

.. module:: modulegraph.zipio
   :synopsis: Read-only filesystem access with ZIP support

This module contains a number of functions that mirror functions found
in :mod:`os` and :mod:`os.path`, but have support for data inside
zipfiles as well as regular filesystem objects.

The *path* argument of all functions below can refer to an object
on the filesystem, but can also refer to an entry inside a zipfile. In
the latter case, a prefix of *path* will be the name of zipfile while
the rest refers to an object in that zipfile. As an example, when
``somepath/mydata.zip`` is a zipfile the path ``somepath/mydata.zip/somefile.txt``
will refer to ``somefile.txt`` inside the zipfile.

.. function:: open(path[, mode])

   Open a file, like :func:`the built-in open function <__builtin__.open>`.

   The *mode* defaults to ``"r"`` and must be either ``"r"`` or ``"rb"``.

.. function:: listdir(path)

   List the contents of a directory, like :func:`os.listdir`.


.. function:: isfile(path)

   Returns true if *path* exists and refers to a file.

   Raises IOError when *path* doesn't exist at all.

   Based on :func:`os.path.isfile`


.. function:: isdir(path)

   Returns true if *path* exists and refers to a directory.

   Raises IOError when *path* doesn't exist at all.

   Based on :func:`os.path.isdir`


.. function:: islink(path)

   Returns true if *path* exists and refers to a symbolic link.

   Raises IOError when *path* doesn't exist at all.

   Based on :func:`os.path.islink`


.. function:: readlink(path)

   Returns the contents of a symbolic link, like :func:`os.readlink`.

.. function:: getmtime(path)

   Returns the last modifiction time of a file or directory, like
   :func:`os.path.getmtime`.

.. function:: getmode(path)

   Returns the UNIX file mode for a file or directory, like the
   *st_mode* attribute in the result of :func:`os.stat`.
