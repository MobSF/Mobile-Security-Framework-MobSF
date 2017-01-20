import hashlib
import collections

from androguard.core import androconf
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *
from androguard.core.analysis.analysis import *
from androguard.decompiler.decompiler import *
from androguard.misc import save_session, load_session

class Session(object):

    def __init__(self):
        self.setupObjects()


    def save(self, filename):
        save_session([self.analyzed_files,
                      self.analyzed_digest,
                      self.analyzed_apk,
                      self.analyzed_dex], filename)

    def load(self, filename):
        self.analyzed_files, self.analyzed_digest, self.analyzed_apk, self.analyzed_dex = load_session(filename)

    def setupObjects(self):
        self.analyzed_files = collections.OrderedDict()
        self.analyzed_digest = {}
        self.analyzed_apk = {}
        self.analyzed_dex = {}

    def reset(self):
        self.setupObjects()

    def isOpen(self):
        return self.analyzed_digest != {}

    def addAPK(self, filename, data):
        digest = hashlib.sha256(data).hexdigest()
        androconf.debug("add APK:%s" % digest)
        apk = APK(data, True)
        self.analyzed_apk[digest] = apk
        self.analyzed_files[filename].append(digest)
        self.analyzed_digest[digest] = filename
        androconf.debug("added APK:%s" % digest)
        return (digest, apk)

    def addDEX(self, filename, data):
        digest = hashlib.sha256(data).hexdigest()
        androconf.debug("add DEX:%s" % digest)

        d = DalvikVMFormat(data)
        androconf.debug("VMAnalysis ...")
        dx = newVMAnalysis(d)
        dx.create_xref()

        d.set_decompiler(DecompilerDAD(d, dx))

        androconf.debug("added DEX:%s" % digest)

        self.analyzed_dex[digest] = (d, dx)
        self.analyzed_files[filename].append(digest)
        self.analyzed_digest[digest] = filename

        return (digest, d, dx)

    def add(self, filename, raw_data):
        ret = is_android_raw(raw_data)
        if ret:
            self.analyzed_files[filename] = []
            digest = hashlib.sha256(raw_data).hexdigest()
            if ret == "APK":
                apk_digest, apk = self.addAPK(filename, raw_data)
                self.addDEX(filename, apk.get_dex())
            elif ret == "DEX":
                self.addDEX(filename, raw_data)
            else:
                return False
            return True
        return False

    def get_classes(self):
        idx = 0
        for filename in self.analyzed_files:
            for digest in self.analyzed_files[filename]:
                if digest in self.analyzed_dex:
                    d, _ = self.analyzed_dex[digest]
                    yield idx, filename, digest, d.get_classes()
            idx += 1

    def get_analysis(self, current_class):
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            if dx.is_class_present(current_class.get_name()):
                return dx
        return None

    def get_format(self, current_class):
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            if dx.is_class_present(current_class.get_name()):
                return d
        return None

    def get_filename_by_class(self, current_class):
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            if dx.is_class_present(current_class.get_name()):
                return self.analyzed_digest[digest]
        return None

    def get_digest_by_class(self, current_class):
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            if dx.is_class_present(current_class.get_name()):
                return digest
        return None

    def get_strings(self):
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            yield digest, self.analyzed_digest[digest], dx.get_strings_analysis()

    def get_nb_strings(self):
        nb = 0
        for digest in self.analyzed_dex:
            d, dx = self.analyzed_dex[digest]
            nb += len(dx.get_strings_analysis())
        return nb
