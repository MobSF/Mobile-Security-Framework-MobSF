from PySide import QtCore, QtGui

from androguard.core import androconf
from androguard.gui.xrefwindow import XrefDialogClass
from androguard.gui.sourcewindow import SourceWindow
from androguard.gui.helpers import classdot2class, Signature

class TreeWindow(QtGui.QTreeWidget):
    def __init__(self, parent=None, win=None, session=None):
        super(TreeWindow, self).__init__(parent)
        self.itemDoubleClicked.connect(self.itemDoubleClickedHandler)
        self.mainwin = win
        self.session = session
        self.createActions()
        self.header().close()
        self.root_path_node = ({}, self)

        self.setupCaches()

    def setupCaches(self):
        self._reverse_cache = {}

    def fill(self):
        '''Parse all the paths (['Lcom/example/myclass/MyActivity$1;', ...])
           and build a tree using the QTreeWidgetItem insertion method.'''
        androconf.debug("Fill classes tree")

        for idx, filename, digest, classes in self.session.get_classes():
            for c in sorted(classes, key=lambda c: c.name):
                sig = Signature(c)
                path_node = self.root_path_node

                path = None
                if sig.class_path == []:
                    path = '.'
                    if path not in path_node[0]:
                        path_node[0][path] = ({}, QtGui.QTreeWidgetItem(path_node[1]))
                        path_node[0][path][1].setText(0, path)
                    path_node = path_node[0][path]
                else:
                    # Namespaces
                    for path in sig.class_path:
                        if path not in path_node[0]:
                            path_node[0][path] = ({}, QtGui.QTreeWidgetItem(path_node[1]))
                            path_node[0][path][1].setText(0, path)
                        path_node = path_node[0][path]

                # Class
                path_node[0][path] = ({}, QtGui.QTreeWidgetItem(path_node[1]))

                class_name = sig.class_name

                if idx > 0:
                    class_name += "@%d" % idx

                c.current_title = class_name
                self._reverse_cache[path_node[0][path][1]] = (c,
                                                              filename,
                                                              digest)


                path_node[0][path][1].setText(0, class_name)


    def itemDoubleClickedHandler(self, item, column):
        '''Signal sent by PySide when a tree element is clicked'''

        androconf.debug("item %s has been double clicked at column %s" % (str(item), str(column)))
        if item.childCount() != 0:
            self.mainwin.showStatus("Sources not available. %s is not a class" % path)
            return

        current_class, current_filename, current_digest = self._reverse_cache[item]
        self.mainwin.openSourceWindow(current_class)

    def createActions(self):
        self.xrefAct = QtGui.QAction("Xref from/to...", self,
#                shortcut=QtGui.QKeySequence("CTRL+B"),
                statusTip="List the references where this element is used",
                triggered=self.actionXref)
        self.expandAct = QtGui.QAction("Expand...", self,
                statusTip="Expand all the subtrees",
                triggered=self.actionExpand)
        self.collapseAct = QtGui.QAction("Collapse...", self,
                statusTip="Collapse all the subtrees",
                triggered=self.actionCollapse)

    def actionXref(self):
        item = self.currentItem()
        if item.childCount() != 0:
            self.mainwin.showStatus("Xref not availables")
            return

        current_class, _, _ = self._reverse_cache[item]

        current_analysis = self.session.get_analysis(current_class)
        if not current_analysis:
            self.mainwin.showStatus("No xref returned (no analysis object).")
            return

        print current_analysis
        class_analysis = current_analysis.get_class_analysis(current_class.get_name())
        if not class_analysis:
            self.mainwin.showStatus("No xref returned (no class_analysis object).")
            return

        print class_analysis

        xwin = XrefDialogClass(parent=self.mainwin, win=self.mainwin, current_class=current_class, class_analysis=class_analysis)
        xwin.show()

    def expand_children(self, item):
        self.expandItem(item)
        for i in range(item.childCount()):
            self.expand_children(item.child(i))

    def actionExpand(self):
        self.expand_children(self.currentItem())

    def collapse_children(self, item):
        for i in range(item.childCount()):
            self.collapse_children(item.child(i))
        self.collapseItem(item)

    def actionCollapse(self):
        self.collapse_children(self.currentItem())

    def contextMenuEvent(self, event):
        menu = QtGui.QMenu(self)
        menu.addAction(self.xrefAct)
        menu.addAction(self.expandAct)
        menu.addAction(self.collapseAct)
        menu.exec_(event.globalPos())
