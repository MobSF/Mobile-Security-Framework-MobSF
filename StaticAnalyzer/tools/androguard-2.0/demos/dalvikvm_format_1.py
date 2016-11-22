#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androguard.core.bytecodes import dvm
from androguard.util import read

TEST = "./examples/dalvik/test/bin/classes.dex"

j = dvm.DalvikVMFormat(read(TEST, binary=False))

# SHOW CLASS (verbose)
j.show()

# SHOW FIELDS
for i in j.get_fields():
    print i.get_access_flags(), i.get_name(), i.get_descriptor()

print

# SHOW METHODS
for i in j.get_methods():
    print i.get_access_flags(), i.get_name(), i.get_descriptor()
