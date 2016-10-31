#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core import androconf
from androguard.util import read


FILENAME_INPUT = "examples/android/TestsAndroguard/bin/classes.dex"
FILENAME_OUTPUT = "./toto.dex"

androconf.set_debug()

vm = dvm.DalvikVMFormat(read(FILENAME_INPUT))

print hex(vm.header.link_off), hex(vm.header.link_size)
vm.header.link_off, vm.header.link_size = 0x41414141, 0x1337
print hex(vm.header.link_off), hex(vm.header.link_size)

new_dex = vm.save()

with open(FILENAME_OUTPUT, "wb") as fd:
	fd.write(new_dex)
