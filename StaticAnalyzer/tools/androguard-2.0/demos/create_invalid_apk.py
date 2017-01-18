#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis
from androguard.core import androconf


def patch_dex(m):
    for i in m.get_methods():
        if i.get_class_name() == "Lre/androguard/android/invalid/MainActivity;":
            #if i.get_name() == "testStrings":
            #    instructions = [ins for ins in i.get_instructions()]
            #    instructions[0].BBBB = 10000
            #    i.set_instructions(instructions)
            if i.get_name() == "testInstances":
                instructions = [ins for ins in i.get_instructions()]
                instructions[0].BBBB = 0x4141
                i.set_instructions(instructions)

FILENAME_INPUT = "./examples/android/Invalid/Invalid.apk"
FILENAME_OUTPUT = "./toto.apk"

androconf.set_debug()

a = apk.APK(FILENAME_INPUT)
vm = dvm.DalvikVMFormat(a.get_dex())
vmx = analysis.VMAnalysis(vm)

patch_dex(vm)

new_dex = vm.save()

a.new_zip(filename=FILENAME_OUTPUT,
          deleted_files="(META-INF/.)",
          new_files={"classes.dex": new_dex})

# Please configure your keystore !! :) follow the tutorial on android website
apk.sign_apk(FILENAME_OUTPUT, "./keystore/keystore1", "tototo")
