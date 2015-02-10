# Radare !

from r2 import r_bin
from r2 import r_asm
from r2 import r_anal
from r2 import r_core

from miasm.arch.arm_arch import arm_mn
from miasm.core.bin_stream import  bin_stream
from miasm.core import asmbloc


class ARM2 :
    def __init__(self) :
        b = r_bin.RBin ()
        b.load("./apks/exploits/617efb2d51ad5c4aed50b76119ad880c6adcd4d2e386b3170930193525b0563d", None)
        baddr= b.get_baddr()
        print '-> Sections'
        for i in b.get_sections ():
            print 'offset=0x%08x va=0x%08x size=%05i %s' % (i.offset, baddr+i.rva, i.size, i.name)

        core = r_core.RCore()
        core.config.set_i("io.va", 1)
        core.config.set_i("anal.split", 1)

        core.file_open("./apks/exploits/617efb2d51ad5c4aed50b76119ad880c6adcd4d2e386b3170930193525b0563d", 0, 0)
        core.bin_load( None )

        core.anal_all()

        for fcn in core.anal.get_fcns() :
            print type(fcn), fcn.type, "%x" % fcn.addr, fcn.ninstr, fcn.name
            #                    if (fcn.type == FcnType_FCN or fcn.type == FcnType_SYM):

        for s in core.bin.get_entries() :
            print s, type(s), s.rva, "%x" % s.offset


        #a = r_asm.RAsm()
        for s in core.bin.get_symbols() :
            print s, s.name, s.rva, s.offset, s.size
            if s.name == "rootshell" :
                #print core.disassemble_bytes( 0x8000 + s.offset, s.size )
               
                #core.assembler.mdisassemble( 0x8000 + s.offset, s.size )
                z = core.op_anal( 0x8000 + s.offset )
                print z.mnemonic

                raise("oo")
                
                print core.bin.bins, core.bin.user
                d = core.bin.read_at( 0x8000 + s.offset, x, s.size )
                print d
                raise("ooo")
                j = 0
                while j < s.size :
                    v = core.disassemble( 0x8000 + s.offset + j )
                    v1 = core.op_str( 0x8000 + s.offset + j )

                    print v1
                #    print 0x8000 + s.offset + j, j, v.inst_len, v.buf_asm
                    j += v.inst_len

                #for i in core.asm_bwdisassemble(s.rva, 4, s.size/4) :
                #    print "la", i
        #    print a.mdisassemble( 20, 0x90 ) #"main", "main" ) #s.name )

