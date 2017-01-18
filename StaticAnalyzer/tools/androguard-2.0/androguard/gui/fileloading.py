from androguard.core import androconf
from PySide import QtCore

from androguard.misc import *

import os.path
import traceback

class FileLoadingThread(QtCore.QThread):

    def __init__(self, session, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.session = session

        self.file_path = None
        self.incoming_file = ()

    def load(self, file_path):
        self.file_path = file_path
        if file_path.endswith(".ag"):
            self.incoming_file = (file_path, 'SESSION')
        else:
            file_type = androconf.is_android(file_path)
            self.incoming_file = (file_path, file_type)
        self.start(QtCore.QThread.LowestPriority)

    def run(self):
        if self.incoming_file:
            try:
                file_path, file_type = self.incoming_file
                if file_type in ["APK", "DEX", "DEY"]:
                    ret = self.session.add(file_path,
                                           open(file_path, 'r').read())
                    self.emit(QtCore.SIGNAL("loadedFile(bool)"), ret)
                elif file_type == "SESSION" :
                    self.session.load(file_path)
                    self.emit(QtCore.SIGNAL("loadedFile(bool)"), True)
            except Exception as e:
                androconf.debug(e)
                androconf.debug(traceback.format_exc())
                self.emit(QtCore.SIGNAL("loadedFile(bool)"), False)

            self.incoming_file = []
        else:
            self.emit(QtCore.SIGNAL("loadedFile(bool)"), False)
