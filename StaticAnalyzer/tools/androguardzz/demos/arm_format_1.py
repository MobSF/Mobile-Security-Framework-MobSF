#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "/core")
sys.path.append(PATH_INSTALL + "/core/bytecodes")
sys.path.append(PATH_INSTALL + "/core/assembly/")
sys.path.append(PATH_INSTALL + "/core/assembly/libassembly")

import assembly
assembly.ASM()

#import arm
#arm.ARM()

#a = apk.APK( TEST )
#a.show()

