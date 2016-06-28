# -*- coding: utf_8 -*-
"""
Module providing the shared functions for static analysis of iOS and Android
"""
import os
import hashlib
import io
import zipfile
import subprocess

from MobSF.utils import PrintException

def FileSize(APP_PATH):
    """Return the size of the file."""
    return round(float(os.path.getsize(APP_PATH)) / (1024 * 1024),2)

def HashGen(APP_PATH):
    """Generate and return sha1 and sha256 as a tupel."""
    try:
        print "[INFO] Generating Hashes"
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        BLOCKSIZE = 65536
        with io.open(APP_PATH, mode='rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha1val = sha1.hexdigest()
        sha256val=sha256.hexdigest()
        return sha1val, sha256val
    except:
        PrintException("[ERROR] Generating Hashes")

def Unzip(APP_PATH, EXT_PATH):
    print "[INFO] Unzipping"
    try:
        files=[]
        with zipfile.ZipFile(APP_PATH, "r") as z:
                z.extractall(EXT_PATH)
                files=z.namelist()
        return files
    except:
        PrintException("[ERROR] Unzipping Error")
        if platform.system()=="Windows":
            print "\n[INFO] Not yet Implemented."
        else:
            print "\n[INFO] Using the Default OS Unzip Utility."
            try:
                subprocess.call(['unzip', '-o', '-q', APP_PATH, '-d', EXT_PATH])
                dat=subprocess.check_output(['unzip','-qq','-l',APP_PATH])
                dat=dat.split('\n')
                x=['Length   Date   Time   Name']
                x=x+dat
                return x
            except:
                PrintException("[ERROR] Unzipping Error")
