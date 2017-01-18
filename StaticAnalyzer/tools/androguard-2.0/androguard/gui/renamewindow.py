from PySide import QtCore, QtGui
from androguard.core import androconf

class RenameDialog(QtGui.QDialog):
    '''
        parent: SourceWindow that started the new XrefDialog
    '''

    def __init__(self, parent=None, win=None, element="", info=()):
        super(RenameDialog, self).__init__(parent)
    
        self.sourceWin = parent
        self.info = info
        self.element = element
        title = "Rename: " + element
        self.setWindowTitle(title)

        layout = QtGui.QGridLayout()
        question = QtGui.QLabel("Please enter new name:")
        layout.addWidget(question, 0, 0)
        self.lineEdit = QtGui.QLineEdit()
        layout.addWidget(self.lineEdit, 0, 1)
        self.buttonOK = QtGui.QPushButton("OK", self)
        layout.addWidget(self.buttonOK, 1, 1)
        self.buttonCancel = QtGui.QPushButton("Cancel", self)
        layout.addWidget(self.buttonCancel, 1, 0)

        self.lineEdit.setText(self.element)

        self.setLayout(layout)

        self.buttonCancel.clicked.connect(self.cancelClicked)
        self.buttonOK.clicked.connect(self.okClicked)

    def cancelClicked(self):
        self.close()

    def okClicked(self):
        self.sourceWin.renameElement(self.element, self.lineEdit.text(), self.info)
        self.close()
    
