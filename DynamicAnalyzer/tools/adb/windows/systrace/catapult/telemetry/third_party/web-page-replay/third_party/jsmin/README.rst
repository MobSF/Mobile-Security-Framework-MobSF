=====
jsmin
=====

JavaScript minifier.

Usage
=====

.. code:: python

 from jsmin import jsmin
 with open('myfile.js') as js_file:
     minified = jsmin(js_file.read())

You can run it as a commandline tool also::

  python -m jsmin myfile.js

NB: ``jsmin`` makes no attempt to be compatible with
`ECMAScript 6 / ES.next / Harmony <http://wiki.ecmascript.org/doku.php?id=harmony:specification_drafts>`_.
The current maintainer does not intend to add ES6-compatibility. If you would
like to take over maintenance and update ``jsmin`` for ES6, please contact
`Tikitu de Jager <mailto:tikitu+jsmin@logophile.org>`_. Pull requests are also
welcome, of course, but my time to review them is somewhat limited these days.

If you're using ``jsmin`` on ES6 code, though, you might find the ``quote_chars``
parameter useful:

.. code:: python

 from jsmin import jsmin
 with open('myfile.js') as js_file:
     minified = jsmin(js_file.read(), quote_chars="'\"`")


Where to get it
===============

* install the package `from pypi <https://pypi.python.org/pypi/jsmin/>`_
* get the latest release `from latest-release on github <https://github.com/tikitu/jsmin/tree/latest-release/jsmin>`_
* get the development version `from master on github <https://github.com/tikitu/jsmin/>`_

Contributing
============

`Issues <https://github.com/tikitu/jsmin/issues>`_ and `Pull requests <https://github.com/tikitu/jsmin/pulls>`_
will be gratefully received on Github. The project used to be hosted
`on bitbucket <https://bitbucket.org/dcs/jsmin/>`_ and old issues can still be
found there.

If possible, please make separate pull requests for tests and for code: tests will be added to the `latest-release` branch while code will go to `master`.

Unless you request otherwise, your Github identity will be added to the contributor's list below; if you prefer a
different name feel free to add it in your pull request instead. (If you prefer not to be mentioned you'll have to let
the maintainer know somehow.)

Build/test status
=================

Both branches are tested with Travis: https://travis-ci.org/tikitu/jsmin

The `latest-release` branch (the version on PyPI plus any new tests) is tested against CPython 2.6, 2.7, 3.2, and 3.3.
Currently:

.. image:: https://travis-ci.org/tikitu/jsmin.png?branch=latest-release

If that branch is failing that means there's a new test that fails on *the latest released version on pypi*, with no fix yet
released.

The `master` branch (development version, might be ahead of latest released version) is tested against CPython 2.6, 2.7, 3.2, and
3.3. Currently:

.. image:: https://travis-ci.org/tikitu/jsmin.png?branch=master

If `master` is failing don't use it, but as long as `latest-release` is passing the pypi release should be ok.

Contributors (chronological commit order)
=========================================

* `Dave St.Germain <https://bitbucket.org/dcs>`_ (original author)
* `Hans weltar <https://bitbucket.org/hansweltar>`_
* `Tikitu de Jager <mailto:tikitu+jsmin@logophile.org>`_ (current maintainer)
* https://bitbucket.org/rennat
* `Nick Alexander <https://bitbucket.org/ncalexan>`_
* `Gennady Kovshenin <https://github.com/soulseekah>`_
* `Matt Molyneaux <https://github.com/moggers87>`_
