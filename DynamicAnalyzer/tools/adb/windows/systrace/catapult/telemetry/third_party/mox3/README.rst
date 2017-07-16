Mox3 - Mock object framework for Python 3
=========================================

Mox3 is an unofficial port of the Google mox framework
(http://code.google.com/p/pymox/) to Python 3. It was meant to be as compatible
with mox as possible, but small enhancements have been made. The library was
tested on Python version 3.2, 2.7 and 2.6.

Use at your own risk ;) 

To install:

  $ python setup.py install

Running Tests
-------------
The testing system is based on a combination of tox and testr. The canonical
approach to running tests is to simply run the command `tox`. This will
create virtual environments, populate them with depenedencies and run all of
the tests that OpenStack CI systems run. Behind the scenes, tox is running
`testr run --parallel`, but is set up such that you can supply any additional
testr arguments that are needed to tox. For example, you can run:
`tox -- --analyze-isolation` to cause tox to tell testr to add
--analyze-isolation to its argument list.

It is also possible to run the tests inside of a virtual environment
you have created, or it is possible that you have all of the dependencies
installed locally already. In this case, you can interact with the testr
command directly. Running `testr run` will run the entire test suite. `testr
run --parallel` will run it in parallel (this is the default incantation tox
uses.) More information about testr can be found at:
http://wiki.openstack.org/testr

Basic Usage
-----------
  
The basic usage of mox3 is the same as with mox, but the initial import should
be made from the mox3 module:

  from mox3 import mox

To learn how to use mox3 you may check the documentation of the original mox
framework:

  http://code.google.com/p/pymox/wiki/MoxDocumentation

Original Copyright
------------------

Mox is Copyright 2008 Google Inc, and licensed under the Apache
License, Version 2.0; see the file COPYING.txt for details.  If you would
like to help us improve Mox, join the group.

OpenStack Fork
--------------

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/mox3
* Source: http://git.openstack.org/cgit/openstack/mox3
* Bugs: http://bugs.launchpad.net/python-mox3
