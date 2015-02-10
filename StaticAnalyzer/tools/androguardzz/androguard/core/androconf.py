# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

import sys, os, logging, types, random, string

ANDROGUARD_VERSION = "1.9"

def get_ascii_string(s) :
    try :
        return s.decode("ascii")
    except UnicodeDecodeError :
        d = ""
        for i in s :
            if ord(i) < 128 :
                d += i
            else :
                d += "%x" % ord(i)
        return d

class Color:
    Normal = "\033[0m"
    Black = "\033[30m"
    Red = "\033[31m"
    Green = "\033[32m"
    Yellow = "\033[33m"
    Blue = "\033[34m"
    Purple = "\033[35m"
    Cyan = "\033[36m"
    Grey = "\033[37m"
    Bold = "\033[1m"

CONF = {
    "BIN_DED": "ded.sh",
    "PATH_DED": "./decompiler/ded/",
    "PATH_DEX2JAR": "./decompiler/dex2jar/",
    "BIN_DEX2JAR": "dex2jar.sh",
    "PATH_JAD": "./decompiler/jad/",
    "BIN_JAD": "jad",
    "PRETTY_SHOW": 1,

    "TMP_DIRECTORY": "/tmp/",

    # Full python or mix python/c++ (native)
    #"ENGINE" : "automatic",
    "ENGINE": "python",

    "RECODE_ASCII_STRING" : False,
    "RECODE_ASCII_STRING_METH" : get_ascii_string,

    "DEOBFUSCATED_STRING" : True,
#    "DEOBFUSCATED_STRING_METH" : get_deobfuscated_string,

    "PATH_JARSIGNER" : "jarsigner",

    "COLORS" : {
        "OFFSET" : Color.Yellow,
        "OFFSET_ADDR" : Color.Green,
        "INSTRUCTION_NAME" : Color.Yellow,
        "BRANCH_FALSE" : Color.Red,
        "BRANCH_TRUE" : Color.Green,
        "BRANCH" : Color.Blue,
        "EXCEPTION" : Color.Cyan,
        "BB" : Color.Purple,
        "NOTE" : Color.Red,
        "NORMAL" : Color.Normal,
    },

    "PRINT_FCT" : sys.stdout.write,

    "LAZY_ANALYSIS" : False,

    "MAGIC_PATH_FILE" : None,
}

def default_colors(obj) :
  CONF["COLORS"]["OFFSET"] = obj.Yellow
  CONF["COLORS"]["OFFSET_ADDR"] = obj.Green
  CONF["COLORS"]["INSTRUCTION_NAME"] = obj.Yellow
  CONF["COLORS"]["BRANCH_FALSE"] = obj.Red
  CONF["COLORS"]["BRANCH_TRUE"] = obj.Green
  CONF["COLORS"]["BRANCH"] = obj.Blue
  CONF["COLORS"]["EXCEPTION"] = obj.Cyan
  CONF["COLORS"]["BB"] = obj.Purple
  CONF["COLORS"]["NOTE"] = obj.Red
  CONF["COLORS"]["NORMAL"] = obj.Normal

def disable_colors() :
  """ Disable colors from the output (color = normal)"""
  for i in CONF["COLORS"] :
    CONF["COLORS"][i] = Color.normal

def remove_colors() :
  """ Remove colors from the output (no escape sequences)"""
  for i in CONF["COLORS"] :
    CONF["COLORS"][i] = ""

def enable_colors(colors) :
  for i in colors :
    CONF["COLORS"][i] = colors[i]

def save_colors() :
  c = {}
  for i in CONF["COLORS"] :
    c[i] = CONF["COLORS"][i]
  return c

def long2int( l ) :
    if l > 0x7fffffff :
        l = (0x7fffffff & l) - 0x80000000
    return l

def long2str(l):
    """Convert an integer to a string."""
    if type(l) not in (types.IntType, types.LongType):
        raise ValueError, 'the input must be an integer'

    if l < 0:
        raise ValueError, 'the input must be greater than 0'
    s = ''
    while l:
        s = s + chr(l & 255L)
        l >>= 8

    return s

def str2long(s):
    """Convert a string to a long integer."""
    if type(s) not in (types.StringType, types.UnicodeType):
        raise ValueError, 'the input must be a string'

    l = 0L
    for i in s:
        l <<= 8
        l |= ord(i)

    return l

def random_string() :
    return random.choice( string.letters ) + ''.join([ random.choice(string.letters + string.digits) for i in range(10 - 1) ] )

def is_android(filename) :
    """Return the type of the file

        @param filename : the filename
        @rtype : "APK", "DEX", "ELF", None 
    """
    if not filename:
        return None

    fd = open( filename, "r")
    val = None

    f_bytes = fd.read(7)

    val = is_android_raw( f_bytes )

    fd.close()
    return val

def is_android_raw(raw):
    val = None
    f_bytes = raw[:7]

    if f_bytes[0:2] == "PK":
        val = "APK"
    elif f_bytes[0:3] == "dex":
        val = "DEX"
    elif f_bytes[0:3] == "dey":
        val = "DEY"
    elif f_bytes[0:7] == "\x7fELF\x01\x01\x01":
        val = "ELF"
    elif f_bytes[0:4] == "\x03\x00\x08\x00":
        val = "AXML"
    elif f_bytes[0:4] == "\x02\x00\x0C\x00":
        val = "ARSC"

    return val

def is_valid_android_raw(raw) :
  return raw.find("classes.dex") != -1

# from scapy
log_andro = logging.getLogger("andro")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
log_andro.addHandler(console_handler)
log_runtime = logging.getLogger("andro.runtime")          # logs at runtime
log_interactive = logging.getLogger("andro.interactive")  # logs in interactive functions
log_loading = logging.getLogger("andro.loading")          # logs when loading andro

def set_lazy() :
  CONF["LAZY_ANALYSIS"] = True

def set_debug() :
    log_andro.setLevel( logging.DEBUG )

def get_debug() :
    return log_andro.getEffectiveLevel() == logging.DEBUG

def warning(x):
    log_runtime.warning(x)
    import traceback
    traceback.print_exc()

def error(x) :
    log_runtime.error(x)
    raise()

def debug(x) :
    log_runtime.debug(x)
    
def set_options(key, value) :
    CONF[ key ] = value

def save_to_disk(buff, output) :
    fd = open(output, "w")
    fd.write(buff)
    fd.close()

def rrmdir( directory ):
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir( directory )

