# !/usr/bin/python
# coding=utf-8
import io
import logging
import os
import struct

logger = logging.getLogger(__name__)


class TinyELFFile(object):
    """from pyelftools."""

    def __init__(self, stream):
        self.stream = stream
        self.stream.seek(0)
        self.magic = self.stream.read(4)
        ei_class = self.stream.read(1)
        if ei_class == b'\x01':
            self.elfclass = 32
        elif ei_class == b'\x02':
            self.elfclass = 64
        else:
            raise Exception('Invalid EI_CLASS %s' % repr(ei_class))
        ei_data = self.stream.read(1)
        if ei_data == b'\x01':
            self.little_endian = True
        elif ei_data == b'\x02':
            self.little_endian = False
        else:
            raise Exception('Invalid EI_DATA %s' % repr(ei_data))
        self.unpack_endian = '<' if self.little_endian else '>'
        self.stream.seek(0)
        self.header = {
            'e_ident': {
                'EI_MAG': [self.unpack_byte() for i in range(4)],
                'EI_CLASS': self.unpack_byte(),
                'EI_DATA': self.unpack_byte(),
                'EI_VERSION': self.unpack_byte(),
                'EI_OSABI': self.unpack_byte(),
                'EI_ABIVERSION': self.unpack_byte(),
                'Padding': [self.unpack_byte() for i in range(7)],
            },
            'e_type': self.unpack_half(),
            'e_machine': self.unpack_half(),
            'e_version': self.unpack_word(),
            'e_entry': self.unpack_addr(),
            'e_phoff': self.unpack_offset(),
            'e_shoff': self.unpack_offset(),
            'e_flags': self.unpack_word(),
            'e_ehsize': self.unpack_half(),
            'e_phentsize': self.unpack_half(),
            'e_phnum': self.unpack_half(),
            'e_shentsize': self.unpack_half(),
            'e_shnum': self.unpack_half(),
            'e_shstrndx': self.unpack_half(),
        }
        xxx = self.decode_shdr(
            self.header['e_shoff']
            + self.header['e_shstrndx']
            * self.header['e_shentsize'])
        self._file_stringtable_section = xxx['sh_offset']

    def decode_shdr(self, off):
        self.stream.seek(off)
        elf_shdr = {
            'sh_name': self.unpack_word(),
            'sh_type': self.unpack_word(),
            'sh_flags': self.unpack_xword(),
            'sh_addr': self.unpack_addr(),
            'sh_offset': self.unpack_offset(),
            'sh_size': self.unpack_xword(),
            'sh_link': self.unpack_word(),
            'sh_info': self.unpack_word(),
            'sh_addralign': self.unpack_xword(),
            'sh_entsize': self.unpack_xword(),
        }
        return elf_shdr

    def decode_sym(self, off):
        self.stream.seek(off)
        elf_sym = {}
        elf_sym['st_name'] = self.unpack_word()
        if self.elfclass == 32:
            elf_sym['st_value'] = self.unpack_addr()
            elf_sym['st_size'] = self.unpack_word()
        else:
            pass
        st_info_struct = self.unpack_byte()
        st_info_bind = st_info_struct >> 4 & 0x0F
        st_info_type = st_info_struct & 0x0F
        st_other_struct = self.unpack_byte()
        st_other_visibility = st_other_struct & 0x07
        elf_sym['st_info'] = {
            'bind': st_info_bind,
            'type': st_info_type,
        }
        elf_sym['st_other'] = {
            'visibility': st_other_visibility,
        }
        elf_sym['st_shndx'] = self.unpack_half()
        if self.elfclass == 32:
            pass
        else:
            elf_sym['st_value'] = self.unpack_addr()
            elf_sym['st_size'] = self.unpack_xword()
        return elf_sym

    def decode_rel(self, off):
        self.stream.seek(off)
        elf_rel = {
            'r_offset': self.unpack_addr(),
            'r_info': self.unpack_xword(),
        }
        if self.elfclass == 32:
            r_info_sym = (elf_rel['r_info'] >> 8) & 0xFFFFFF
            r_info_type = elf_rel['r_info'] & 0xFF
        else:  # 64
            r_info_sym = (elf_rel['r_info'] >> 32) & 0xFFFFFFFF
            r_info_type = elf_rel['r_info'] & 0xFFFFFFFF
        elf_rel['r_info_sym'] = r_info_sym
        elf_rel['r_info_type'] = r_info_type
        return elf_rel

    def decode_rela(self, off):
        elf_rela = self.decode_rel(off)
        elf_rela['r_addend'] = self.unpack_sxword()
        return elf_rela

    def decode_string(self, off):
        self.stream.seek(off)
        chunksize = 64
        chunks = []
        found = False
        while True:
            chunk = self.stream.read(chunksize)
            end_index = chunk.find(b'\x00')
            if end_index >= 0:
                chunks.append(chunk[:end_index])
                found = True
                break
            else:
                chunks.append(chunk)
            if len(chunk) < chunksize:
                break
        strn = b''.join(chunks) if found else None
        return strn.decode('ascii')

    def unpack_byte(self):
        return struct.unpack(self.unpack_endian + 'B', self.stream.read(1))[0]

    def unpack_half(self):
        return struct.unpack(self.unpack_endian + 'H', self.stream.read(2))[0]

    def unpack_word(self):
        return struct.unpack(self.unpack_endian + 'L', self.stream.read(4))[0]

    def unpack_word64(self):
        return struct.unpack(self.unpack_endian + 'Q', self.stream.read(8))[0]

    def unpack_addr(self):
        if self.elfclass == 32:
            return (struct.unpack(self.unpack_endian
                    + 'L', self.stream.read(4))[0])
        else:
            return (struct.unpack(self.unpack_endian
                    + 'Q', self.stream.read(8))[0])

    def unpack_offset(self):
        return self.unpack_addr()

    def unpack_sword(self):
        return struct.unpack(self.unpack_endian + 'l', self.stream.read(4))[0]

    def unpack_xword(self):
        if self.elfclass == 32:
            return (struct.unpack(self.unpack_endian
                    + 'L', self.stream.read(4))[0])
        else:
            return (struct.unpack(self.unpack_endian
                    + 'Q', self.stream.read(8))[0])

    def unpack_sxword(self):
        if self.elfclass == 32:
            return (struct.unpack(self.unpack_endian
                    + 'l', self.stream.read(4))[0])
        else:
            return (struct.unpack(self.unpack_endian
                    + 'q', self.stream.read(8))[0])


def check_elf_built(f):
    has_pi = False
    has_sp = False
    has_pi_fg = {
        3: [8],  # EM_386=3,    R_386_RELATIVE=8,
        62: [8],  # EM_X86_64=62,    R_X86_64_RELATIVE=8,
        40: [23, 3],  # EM_ARM=40,    R_ARM_RELATIVE=23,R_ARM_REL32=3,
        183: [1027, 3],  # EM_AARCH64=183,
                         # R_AARCH64_RELATIVE=1027,R_ARM_REL32=3,
        8: [3],  # EM_MIPS=8,    R_MIPS_REL32=3,
    }
    elffile = TinyELFFile(f)
    for i in range(elffile.header['e_shnum']):
        section_header = elffile.decode_shdr(
            elffile.header['e_shoff'] + i * elffile.header['e_shentsize'])
        sectype = section_header['sh_type']
        if sectype in (4, 9):  # SHT_RELA=4,SHT_REL=9,
            if section_header['sh_entsize'] > 0:
                siz = section_header['sh_size'] // section_header['sh_entsize']
                for i in range(siz):
                    elffile.stream.seek(
                        section_header['sh_offset']
                        + i
                        * section_header['sh_entsize'])
                    if section_header['sh_type'] == 9:
                        entry = elffile.decode_rel(
                            section_header['sh_offset']
                            + i
                            * section_header['sh_entsize'])
                    elif section_header['sh_type'] == 4:
                        entry = elffile.decode_rela(
                            section_header['sh_offset']
                            + i
                            * section_header['sh_entsize'])
                    else:
                        continue
                    if (entry['r_info_type']
                            in has_pi_fg.get(elffile.header['e_machine'], [])):
                        if entry['r_info_sym'] == 0:
                            has_pi = True
                            break
    return has_pi, has_sp


def res_analysis(app_dir):
    """Perform the elf analysis."""
    try:
        logger.info('Static Android Resource Analysis Started')
        elf_desc = {
            'html_infected':
                (
                    'Found html files infected by malware.',
                    'high',
                    'The built environment was probably'
                    ' infected by malware, The html file '
                    'used in this APK is infected.')}
        html_an_dic = {}
        for k in list(elf_desc.keys()):
            html_an_dic[k] = []
        resraw = os.path.join(app_dir, 'res', 'raw')
        assets = os.path.join(app_dir, 'assets')
        for resdir in (resraw, assets):
            if os.path.exists(resdir) and os.path.isdir(resdir):
                for pdir, _dirl, filel in os.walk(resdir):
                    for filename in filel:
                        if (filename.endswith('.htm')
                                or filename.endswith('.html')):
                            try:
                                filepath = os.path.join(pdir, filename)
                                buf = ''
                                with io.open(filepath, mode='rb') as filp:
                                    buf = filp.read()
                                if 'svchost.exe' in buf:
                                    html_an_dic['html_infected'].append(
                                        filepath.replace(app_dir, ''))
                            except Exception:
                                pass
        res = []
        for k, filelist in list(html_an_dic.items()):
            if len(filelist):
                descs = elf_desc.get(k)
                res.append({'title': descs[0],
                            'stat': descs[1],
                            'desc': descs[2],
                            'file': ' '.join(filelist),
                            })
        return res

    except Exception:
        logger.exception('Performing Resourse Analysis')


def elf_analysis(app_dir: str) -> list:
    """Perform the elf analysis."""
    try:
        logger.info('Static Android Binary Analysis Started')
        fgs = ['nopie', 'nonpie', 'no-pie']
        elf_desc = {
            'elf_no_pi':
                (
                    'Found elf built without Position Independent Executable'
                    ' (PIE) flag',
                    'high',
                    'In order to prevent an attacker from reliably jumping'
                    ' to, for example, a particular'
                    ' exploited function in memory, Address space layout'
                    ' randomization (ASLR) randomly '
                    'arranges the address space positions of key data areas'
                    ' of a process, including the '
                    'base of the executable and the positions of the stack,'
                    ' heap and libraries. Built with'
                    ' option <strong>-pie</strong>.')}
        elf_an_dic = {}
        for k in list(elf_desc.keys()):
            elf_an_dic[k] = []
        libdir = os.path.join(app_dir, 'lib')
        if os.path.exists(libdir):
            for pdir, _dirl, filel in os.walk(libdir):
                for fname in filel:
                    if fname.endswith('.so'):
                        try:
                            filepath = os.path.join(pdir, fname)
                            f = io.open(filepath, mode='rb')
                            has_pie, has_sg = check_elf_built(f)
                            f.close()
                            if not has_pie:
                                if not any(pie_st in fgs for pie_st in fname):
                                    elf_an_dic['elf_no_pi'].append(
                                        filepath.replace(libdir, 'lib'))
                        except Exception:
                            pass
        res = []
        for k, filelist in list(elf_an_dic.items()):
            if len(filelist):
                descs = elf_desc.get(k)
                res.append({'title': descs[0],
                            'stat': descs[1],
                            'desc': descs[2],
                            'file': ' '.join(filelist),
                            })
        return res

    except Exception:
        logger.exception('Performing Binary Analysis')
