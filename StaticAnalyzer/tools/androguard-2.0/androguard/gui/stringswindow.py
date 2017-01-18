from PySide import QtCore, QtGui
from androguard.gui.xrefwindow import XrefDialogString

class StringsWindow(QtGui.QWidget):
    def __init__(self, parent=None, win=None, session=None):
        super(StringsWindow, self).__init__(parent)
        self.mainwin = win
        self.session = session
        self.title = "Strings"

        self.filterPatternLineEdit = QtGui.QLineEdit()
        self.filterPatternLabel = QtGui.QLabel("&Filter string pattern:")
        self.filterPatternLabel.setBuddy(self.filterPatternLineEdit)
        self.filterPatternLineEdit.textChanged.connect(self.filterRegExpChanged)

        self.stringswindow = StringsValueWindow(self, win, session)

        sourceLayout = QtGui.QVBoxLayout()
        sourceLayout.addWidget(self.stringswindow)
        sourceLayout.addWidget(self.filterPatternLabel)
        sourceLayout.addWidget(self.filterPatternLineEdit)

        self.setLayout(sourceLayout)

    def filterRegExpChanged(self, value):
        regExp = QtCore.QRegExp(value)
        self.stringswindow.proxyModel.setFilterRegExp(regExp)

class StringsValueWindow(QtGui.QTreeView):
    def __init__(self, parent=None, win=None, session=None):
        super(StringsValueWindow, self).__init__(parent)
        self.mainwin = win
        self.session = session
        self.title = "Strings"

        self.reverse_strings = {}

        self.proxyModel = QtGui.QSortFilterProxyModel()
        self.proxyModel.setDynamicSortFilter(True)

        self.model = QtGui.QStandardItemModel(self.session.get_nb_strings(), 4, self)

        self.model.setHeaderData(0, QtCore.Qt.Horizontal, "String")
        self.model.setHeaderData(1, QtCore.Qt.Horizontal, "Usage")
        self.model.setHeaderData(2, QtCore.Qt.Horizontal, "Filename")
        self.model.setHeaderData(3, QtCore.Qt.Horizontal, "Digest")

        row = 0
        for digest, filename, strings_analysis in self.session.get_strings():
            for string_value in strings_analysis:
                self.model.setData(self.model.index(row, 0, QtCore.QModelIndex()), repr(string_value))
                self.model.setData(self.model.index(row, 1, QtCore.QModelIndex()), len(strings_analysis[string_value].get_xref_from()))
                self.model.setData(self.model.index(row, 2, QtCore.QModelIndex()), filename)
                self.model.setData(self.model.index(row, 3, QtCore.QModelIndex()), digest)
                self.reverse_strings[repr(string_value) + digest] = strings_analysis[string_value]
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

        if column == 0:
            xwin = XrefDialogString(parent=self.mainwin, win=self.mainwin, string_analysis=self.reverse_strings[self.model.item(row).text() + self.model.item(row, 3).text()])
            xwin.show()
