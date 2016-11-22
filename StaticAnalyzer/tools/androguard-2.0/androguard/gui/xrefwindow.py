from PySide import QtCore, QtGui
from androguard.core import androconf
from androguard.gui.helpers import display2classmethod, class2func, classmethod2display, method2func

class XrefDialogClass(QtGui.QDialog):
    '''Dialog holding our Xref listview.
        parent: SourceWindow that started the new XrefDialog
        path: complete path of the class we are looking an xref from
        method (optional): method of the class we are looking xref from
        xrefs_list: the list of "Class -> Method" strings representing the xrefs

        path/method are used for the title of the window
        xrefs_list for the content of the QListView
    '''

    def __init__(self, parent=None, win=None, current_class=None, class_analysis=None):
        super(XrefDialogClass, self).__init__(parent)
        self.current_class = current_class
        self.class_analysis = class_analysis

        title = "Xrefs for the class %s" % current_class

        self.setWindowTitle(title)

        xrefs_list = []

        ref_kind_map = {0:"Class instanciation", 1:"Class reference"}

        xrefs_from = class_analysis.get_xref_from()
        for ref_class in xrefs_from:
            for ref_kind, ref_method in xrefs_from[ref_class]:
                xrefs_list.append(('From', ref_kind_map[ref_kind], ref_method, ref_class.get_vm_class()))

        xrefs_to = class_analysis.get_xref_to()
        for ref_class in xrefs_to:
            for ref_kind, ref_method in xrefs_to[ref_class]:
                xrefs_list.append(('To', ref_kind_map[ref_kind], ref_method, ref_class.get_vm_class()))

        closeButton = QtGui.QPushButton("Close")
        closeButton.clicked.connect(self.close)

        xreflayout = QtGui.QGridLayout()
        xrefwin = XrefListView(self, win=win, xrefs=xrefs_list, headers=["Origin", "Kind", "Method"])
        xreflayout.addWidget(xrefwin, 0, 0)

        buttonsLayout = QtGui.QHBoxLayout()
        buttonsLayout.addStretch(1)
        buttonsLayout.addWidget(closeButton)

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addLayout(xreflayout)
        mainLayout.addLayout(buttonsLayout)

        self.setLayout(mainLayout)

class XrefDialogMethod(QtGui.QDialog):
    def __init__(self, parent=None, win=None, current_class=None, class_analysis=None, method_analysis=None):
        super(XrefDialogMethod, self).__init__(parent)
        self.current_class = current_class
        self.class_analysis = class_analysis
        self.method_analysis = method_analysis

        title = "Xrefs for the method %s" % self.method_analysis.method

        self.setWindowTitle(title)

        xrefs_list = []

        xrefs_from = self.method_analysis.get_xref_from()
        for ref_class, ref_method in xrefs_from:
            xrefs_list.append(('From', ref_method, ref_class.get_vm_class()))

        xrefs_to = self.method_analysis.get_xref_to()
        for ref_class, ref_method in xrefs_to:
            xrefs_list.append(('To', ref_method, ref_class.get_vm_class()))

        closeButton = QtGui.QPushButton("Close")
        closeButton.clicked.connect(self.close)

        xreflayout = QtGui.QGridLayout()
        xrefwin = XrefListView(self, win=win, xrefs=xrefs_list)
        xreflayout.addWidget(xrefwin, 0, 0)

        buttonsLayout = QtGui.QHBoxLayout()
        buttonsLayout.addStretch(1)
        buttonsLayout.addWidget(closeButton)

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addLayout(xreflayout)
        mainLayout.addLayout(buttonsLayout)

        self.setLayout(mainLayout)

class XrefDialogField(QtGui.QDialog):
    def __init__(self, parent=None, win=None, current_class=None, class_analysis=None, field_analysis=None):
        super(XrefDialogField, self).__init__(parent)
        self.current_class = current_class
        self.class_analysis = class_analysis
        self.field_analysis = field_analysis

        title = "Xrefs for the field %s" % self.field_analysis.field

        self.setWindowTitle(title)

        xrefs_list = []

        xrefs_read = self.field_analysis.get_xref_read()
        for ref_class, ref_method in xrefs_read:
            xrefs_list.append(('Read', ref_method, ref_class.get_vm_class()))

        xrefs_write = self.field_analysis.get_xref_write()
        for ref_class, ref_method in xrefs_write:
            xrefs_list.append(('Write', ref_method, ref_class.get_vm_class()))

        closeButton = QtGui.QPushButton("Close")
        closeButton.clicked.connect(self.close)

        xreflayout = QtGui.QGridLayout()
        xrefwin = XrefListView(self, win=win, xrefs=xrefs_list)
        xreflayout.addWidget(xrefwin, 0, 0)

        buttonsLayout = QtGui.QHBoxLayout()
        buttonsLayout.addStretch(1)
        buttonsLayout.addWidget(closeButton)

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addLayout(xreflayout)
        mainLayout.addLayout(buttonsLayout)

        self.setLayout(mainLayout)

class XrefDialogString(QtGui.QDialog):
    def __init__(self, parent=None, win=None, string_analysis=None):
        super(XrefDialogString, self).__init__(parent)
        self.string_analysis = string_analysis

        title = "Xrefs for the string %s" % self.string_analysis.value

        self.setWindowTitle(title)

        xrefs_list = []

        xrefs_from = self.string_analysis.get_xref_from()
        for ref_class, ref_method in xrefs_from:
            xrefs_list.append(('From', ref_method, ref_class.get_vm_class()))

        closeButton = QtGui.QPushButton("Close")
        closeButton.clicked.connect(self.close)

        xreflayout = QtGui.QGridLayout()
        xrefwin = XrefListView(self, win=win, xrefs=xrefs_list)
        xreflayout.addWidget(xrefwin, 0, 0)

        buttonsLayout = QtGui.QHBoxLayout()
        buttonsLayout.addStretch(1)
        buttonsLayout.addWidget(closeButton)

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addLayout(xreflayout)
        mainLayout.addLayout(buttonsLayout)

        self.setLayout(mainLayout)

class XrefDialog(QtGui.QDialog):
    '''Dialog holding our Xref listview.
        parent: SourceWindow that started the new XrefDialog
        path: complete path of the class we are looking an xref from
        method (optional): method of the class we are looking xref from
        xrefs_list: the list of "Class -> Method" strings representing the xrefs

        path/method are used for the title of the window
        xrefs_list for the content of the QListView
    '''

    def __init__(self, parent=None, win=None, xrefs_list=None, method=""):
        super(XrefDialog, self).__init__(parent)

        if not isinstance(xrefs_list, list) or len(xrefs_list) == 0:
            androconf.warning("Bad XrefDialog creation")
            return

        if not method:
            title = "Xrefs to %s" % path.split("/")[-1]
        else:
            title = "Xrefs to %s -> %s" % (path.split("/")[-1], method)

        self.setWindowTitle(title)
        layout = QtGui.QGridLayout()
        xrefwin = XrefListView(self, win=win, xrefs=xrefs_list)
        layout.addWidget(xrefwin, 0, 0)
        self.setLayout(layout)

    @classmethod
    def get_xrefs_list(cls, class_item, method=None):
        '''Static method called before creating a XrefDialog
           to check if there are xrefs to display
            method (optional): method of the class we are looking xref from
        '''
        androconf.debug("Getting XREF for %s" % class_item)

        item = class_item
        if method:
            item = method

        return XrefDialog.get_xrefs_list_from_element(item)

    @classmethod
    def get_xrefs_list_from_element(cls, element):
        '''Helper for get_xrefs_list

           element is a ClassDefItem or MethodDefItem

           At the end of the function, we lost if we worked on
           a class or method but we do not care for now.
        '''

        xref_items = element.XREFfrom.items
        androconf.debug("%d XREFs found" % len(xref_items))
#        print xref_items
        xrefs = []
        for xref_item in xref_items:
            class_ = xref_item[0].get_class_name()
            method_ = xref_item[0].get_name()
            descriptor_ = xref_item[0].get_descriptor()
            xrefs.append(classmethod2display(class_, method_, descriptor_))
#        print xrefs
        return xrefs

class XrefListView(QtGui.QWidget):
    def __init__(self, parent=None, win=None, xrefs=None, headers=["Origin", "Method"]):
        super(XrefListView, self).__init__(parent)
        self.parent = parent
        self.mainwin = win
        self.xrefs = xrefs
        self.headers = headers

        self.setMinimumSize(600, 400)

        self.filterPatternLineEdit = QtGui.QLineEdit()
        self.filterPatternLabel = QtGui.QLabel("&Filter origin pattern:")
        self.filterPatternLabel.setBuddy(self.filterPatternLineEdit)
        self.filterPatternLineEdit.textChanged.connect(self.filterRegExpChanged)

        self.xrefwindow = XrefValueWindow(self, win, self.xrefs, self.headers)

        sourceLayout = QtGui.QVBoxLayout()
        sourceLayout.addWidget(self.xrefwindow)
        sourceLayout.addWidget(self.filterPatternLabel)
        sourceLayout.addWidget(self.filterPatternLineEdit)

        self.setLayout(sourceLayout)

    def filterRegExpChanged(self, value):
        regExp = QtCore.QRegExp(value)
        self.xrefwindow.proxyModel.setFilterRegExp(regExp)

    def close(self):
        self.parent.close()

class XrefValueWindow(QtGui.QTreeView):
    def __init__(self, parent=None, win=None, xrefs=None, headers=None):
        super(XrefValueWindow, self).__init__(parent)
        self.parent = parent
        self.mainwin = win
        self.xrefs = xrefs
        self.headers = headers

        self.reverse_strings = {}

        self.proxyModel = QtGui.QSortFilterProxyModel()
        self.proxyModel.setDynamicSortFilter(True)

        self.model = QtGui.QStandardItemModel(len(self.xrefs), len(self.headers), self)

        column = 0
        for header in headers:
            self.model.setHeaderData(column, QtCore.Qt.Horizontal, header)
            column += 1

        row = 0
        for ref in xrefs:
            for column in range(len(self.headers)):
                self.model.setData(self.model.index(row, column, QtCore.QModelIndex()), "%s" % ref[column])
            row += 1

        self.proxyModel.setSourceModel(self.model)

        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setModel(self.proxyModel)
        self.setSortingEnabled(True)
        self.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)

        self.doubleClicked.connect(self.slotDoubleClicked)

    def slotDoubleClicked(self, mi):
        mi = self.proxyModel.mapToSource(mi)
        row = mi.row()
        column = mi.column()

        if column == len(self.headers) - 1:
            data = mi.data()
            xref_method = None
            xref_class = None
            for xref in self.xrefs:
                if str(xref[-2]) == data:
                    xref_method = xref[-2]
                    xref_class = xref[-1]
                    break

            if xref_class and xref_method:
                self.mainwin.openSourceWindow(current_class=xref_class,
                                              method=xref_method)
                self.parent.close()
                return
            else:
                self.mainwin.showStatus("Impossible to find the xref ....")
                return
