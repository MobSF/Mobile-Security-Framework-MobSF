#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis
from androguard.core import androconf


import hashlib

def hexdump(src, length=8, off=0):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
        result.append( b"%04X   %-*s   %s" % (i+off, length*(digits + 1), hexa, text) )
    return b'\n'.join(result)

class MDalvikVMFormat:
    def __init__(self, vm, vmx) :
        self.vm = vm
        self.vmx = vmx

    def modify_instruction(self, class_name, method_name, descriptor, offset, instructions) :
        pass

    def test_save(self) :
        original_buff = self.vm.get_buff()

        b1 = original_buff

        method = self.vm.get_method_descriptor(
            "Lfr/t0t0/android/TestModifActivity;", "onCreate",
            "(Landroid/os/Bundle;)V" )
#        method.show()
#        print hex(method.code_off)

#        instructions = [i for i in method.get_instructions()]
#        ins = instructions[3]
#        print ins
#        ins.BBBB = 12
#        instructions.insert(3, ins)
#        method.set_instructions( instructions )

        b2 = self.vm.save()

        self.check(b1, b2, 40)

        return b2

    def check(self, b1, b2, off) :
        if hashlib.md5( b1 ).hexdigest() != hashlib.md5( b2 ).hexdigest() :
            j = 0
            end = max(len(b1), len(b2))
            while j < end :
                if j < off :
                  j += 1
                  continue

                if j >= len(b1) :
                    print "OUT OF B1 @ OFFSET 0x%x(%d)" % (j,j)
                    raise("ooo")

                if j >= len(b2) :
                    print "OUT OF B2 @ OFFSET 0x%x(%d)" % (j,j)
                    raise("ooo")

                if b1[j] != b2[j] :
                    print "BEGIN @ OFFSET 0x%x" % j
                    print "ORIG : "
                    print hexdump(b1[j - 8: j + 8], off=j-8) + "\n"
                    print "NEW : "
                    print hexdump(b2[j - 8: j + 8], off=j-8) + "\n"

                j += 1


        print "OK"


#TEST = "examples/android/TestsAndroguard/bin/TestsAndroguard.apk"
TEST = "apks/malwares/smszombie/40F3F16742CD8AC8598BF859A23AC290.apk"
FILENAME = "./toto.apk"

androconf.set_debug()

a = apk.APK( TEST )
j = dvm.DalvikVMFormat( a.get_dex() )
x = analysis.VMAnalysis( j )

m = MDalvikVMFormat(j, x)
print j, x, m

new_dex = m.test_save()

a.new_zip(  filename=FILENAME,
            deleted_files="(META-INF/.)", new_files = {
            "classes.dex" : new_dex } )
apk.sign_apk( FILENAME, "./keystore/keystore1", "tototo" )
