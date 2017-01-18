from PySide import QtCore, QtGui
from androguard.core import androconf
from androguard.gui.helpers import class2func, method2func, classdot2func, classdot2class, proto2methodprotofunc
from androguard.gui.renamewindow import RenameDialog
from androguard.gui.xrefwindow import XrefDialogMethod, XrefDialogField

PYGMENTS = True
try:
    from qtconsole.pygments_highlighter import PygmentsHighlighter
    from pygments.lexers import JavaLexer
except:
    PYGMENTS = False

import os

BINDINGS_NAMES = [
    'NAME_PACKAGE', 'NAME_PROTOTYPE', 'NAME_SUPERCLASS', 'NAME_INTERFACE',
    'NAME_FIELD', 'NAME_METHOD_PROTOTYPE', 'NAME_ARG', 'NAME_CLASS_ASSIGNMENT',
    'NAME_PARAM', 'NAME_BASE_CLASS', 'NAME_METHOD_INVOKE', 'NAME_CLASS_NEW',
    'NAME_CLASS_INSTANCE', 'NAME_VARIABLE', 'NAME_CLASS_EXCEPTION'
]

class SourceDocument(QtGui.QTextDocument):
    '''QTextDocument associated with the SourceWindow.'''

    def __init__(self, parent=None, lines=[]):
        super(SourceDocument, self).__init__(parent)
        self.parent = parent

        # Set font to be fixed-width
        font = self.defaultFont()
        font.setFamily("Courier New")
        self.setDefaultFont(font)

        cursor = QtGui.QTextCursor(self) # position=0x0
        state = 0
        self.binding = {}

        # save the cursor position before each interesting element
        for section, L in lines:
            for t in L:
                if t[0] in BINDINGS_NAMES:
                    self.binding[cursor.position()] = t
                cursor.insertText(t[1])

class SourceWindow(QtGui.QTextEdit):
    '''Each tab is implemented as a Source Window class.
       Attributes:
        mainwin: MainWindow
        path: class FQN
        title: last part of the class FQN
        class_item: ClassDefItem i.e. class.java object for which we create the tab
    '''

    def __init__(self, parent=None, win=None, current_class=None, current_title=None, current_filename=None, current_digest=None, session=None):
        super(SourceWindow, self).__init__(parent)
        androconf.debug("New source tab for: %s" % current_class)

        self.mainwin = win
        self.session = session
        self.current_class = current_class
        self.current_title = current_title
        self.current_filename = current_filename
        self.current_digest = current_digest

        self.title = current_title

        self.setReadOnly(True)

        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.CustomContextMenuHandler)

        self.cursorPositionChanged.connect(self.cursor_position_changed)

    def browse_to_method(self, method):
        '''Scroll to the right place were the method is.

           TODO: implement it, because does not work for now.
        '''

        #TODO: we need to find a way to scroll to the right place because
        #      moving the cursor is not enough. Indeed if it is already in the window
        #      it does not do nothing

        #TODO: idea, highlight the method in the screen so we do not have to search for it

        androconf.debug("Browsing to %s -> %s" % (self.current_class, method))

        # debug
#        if False:
#            for k, v in self.doc.infoBlocks.items():
#                print k
#                print v
#                print "-"*10

    def reload_java_sources(self):
        '''Reload completely the sources by asking Androguard
           to decompile it again. Useful when:
            - an element has been renamed to propagate the info
            - the current tab is changed because we do not know what user
              did since then, so we need to propagate previous changes as well
        '''

        androconf.debug("Getting sources for %s" % self.current_class)

        lines = []
        lines.append(("COMMENTS", [("COMMENT", "/*\n * filename:%s\n * digest:%s\n */\n" % (self.current_filename, self.current_digest))]))
        lines.extend(self.current_class.get_source_ext())

        #TODO: delete doc when tab is closed? not deleted by "self" :(
        if hasattr(self, "doc"):
            del self.doc
        self.doc = SourceDocument(parent=self, lines=lines)
        self.setDocument(self.doc)

        #No need to save hightlighter. highlighBlock will automatically be called
        #because we passed the QTextDocument to QSyntaxHighlighter constructor
        if PYGMENTS:
            PygmentsHighlighter(self.doc, lexer=JavaLexer())
        else:
            androconf.debug("Pygments is not present !")

    def display_bytecodes(self):
        androconf.debug("Display bytecodes for %s" % self.current_class)
        self.mainwin.openBytecodeWindow(self.current_class)

    @QtCore.Slot()
    def cursor_position_changed(self):
        '''Used to detect when cursor change position and to auto select word
           underneath it'''
        androconf.debug("cursor_position_changed")

        cur = self.textCursor()
        androconf.debug(cur.position())
        androconf.debug(cur.selectedText())
        if len(cur.selectedText()) == 0:
            cur.select(QtGui.QTextCursor.SelectionType.WordUnderCursor)
            self.setTextCursor(cur)
            androconf.debug("cursor: %s" % cur.selectedText())
        else:
            androconf.debug("cursor: no selection %s" % cur.selectedText())


    def keyPressEvent(self, event):
        '''Keyboard shortcuts'''
        key = event.key()
        if key == QtCore.Qt.Key_X:
            self.actionXref()
        elif key == QtCore.Qt.Key_G:
            self.actionGoto()
        elif key == QtCore.Qt.Key_X:
            self.actionXref()
        elif key == QtCore.Qt.Key_I:
            self.actionInfo()
        elif key == QtCore.Qt.Key_R:
            self.reload_java_sources()
        elif key == QtCore.Qt.Key_B:
            self.display_bytecodes()

    def CustomContextMenuHandler(self, pos):
        menu = QtGui.QMenu(self)
        menu.addAction(QtGui.QAction("Xref ...", self,
                statusTip="List the references where this element is used",
                triggered=self.actionXref))
        menu.addAction(QtGui.QAction("Go to...", self,
                statusTip="Go to element definition",
                triggered=self.actionGoto))
        menu.addAction(QtGui.QAction("Rename...", self,
                statusTip="Rename an element (class, method, ...)",
                triggered=self.actionRename))
        menu.addAction(QtGui.QAction("Info...", self,
                statusTip="Display info of an element (anything useful in the document)",
                triggered=self.actionInfo))
        menu.addAction(QtGui.QAction("Reload sources...", self,
                statusTip="Reload sources (needed when renaming changed other tabs)",
                triggered=self.reload_java_sources))
        menu.addAction(QtGui.QAction("Open bytecodes...", self,
                statusTip="",
                triggered=self.display_bytecodes))
        menu.exec_(QtGui.QCursor.pos())

    def actionXref(self):
        cursor = self.textCursor()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        selection = cursor.selectedText()
        androconf.debug("Xref asked for '%s' (%d, %d)" % (selection, start, end))

        if start not in self.doc.binding.keys():
            self.mainwin.showStatus("Xref not available. No info for: '%s'." % selection)
            return

        class_ = None
        method_ = None
        t = self.doc.binding[start]
        print t

        if t[0] == 'NAME_METHOD_PROTOTYPE':
            method_ = t[1]
            if method_ == self.title:
                method_ = 'init'

            proto_ = t[2].method.proto

            method_class_name = self.current_class.get_name()
            method_name = method_
            method_proto = proto_
            current_analysis = self.session.get_analysis(self.current_class)

            androconf.debug("Found corresponding method: %s %s %s in source file: %s" % (method_class_name, method_name, method_proto, self.current_filename))

            class_analysis = current_analysis.get_class_analysis(self.current_class.get_name())
            if not class_analysis:
                self.mainwin.showStatus("No xref returned (no class_analysis object).")
                return

            method_analysis = class_analysis.get_method_analysis(current_analysis.get_method_by_name(method_class_name, method_name, method_proto))
            print method_analysis
            if not method_analysis:
                self.mainwin.showStatus("No xref returned (no method_analysis object).")
                return

            xwin = XrefDialogMethod(parent=self.mainwin, win=self.mainwin, current_class=self.current_class, class_analysis=class_analysis, method_analysis=method_analysis)
            xwin.show()
        elif t[0] == 'NAME_FIELD':
            field_ = t[3]

            current_analysis = self.session.get_analysis(self.current_class)
            class_analysis = current_analysis.get_class_analysis(self.current_class.get_name())
            if not class_analysis:
                self.mainwin.showStatus("No xref returned (no class_analysis object).")
                return

            field_analysis = class_analysis.get_field_analysis(field_)
            print field_analysis
            if not field_analysis:
                self.mainwin.showStatus("No xref returned (no field_analysis object).")
                return

            xwin = XrefDialogField(parent=self.mainwin, win=self.mainwin, current_class=self.current_class, class_analysis=class_analysis, field_analysis=field_analysis)
            xwin.show()
        else:
            self.mainwin.showStatus("No xref returned.")
            return


        #elif t[0] == 'NAME_METHOD_INVOKE':
        #    class_, method_ = t[2].split(' -> ')
        #    if class_ == 'this':
        #        class_ = self.current_class
        #    else:
        #        class_ = classdot2class(class_)
        #elif t[0] == 'NAME_PROTOTYPE':
        #    class_ = classdot2class(t[2] + '.' + t[1])
        #else:
        #    self.mainwin.showStatus("Xref not available. Info ok: '%s' but object not supported." % selection)
        #    return




    def actionRename(self):
        cursor = self.textCursor()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        selection = cursor.selectedText()
        androconf.debug("Rename asked for '%s' (%d, %d)" % (selection, start, end))

        if start not in self.doc.binding.keys():
            self.mainwin.showStatus("Rename not available. No info for: '%s'." % selection)
            return

        # Double check if we support the renaming for the type of
        # object before poping a new window to the user
        t = self.doc.binding[start]
        if t[0] == 'NAME_METHOD_PROTOTYPE':
            class_ = self.current_class
            method_ = t[1]
            if method_ == self.title:
                method_ = 'init'
            androconf.debug("Found corresponding method: %s -> %s in source file: %s" % (class_, method_, self.current_filename))
        elif t[0] == 'NAME_METHOD_INVOKE':
            class_, method_ = t[2].split(' -> ')
            if class_ == 'this':
                class_ = self.current_class
            androconf.debug("Found corresponding method: %s -> %s in source file: %s" % (class_, method_, self.current_filename))
        elif t[0] == 'NAME_PROTOTYPE':
            class_ = t[2] + '.' + t[1]
            androconf.debug("Found corresponding class: %s in source file: %s" % (class_, self.current_filename))
        elif t[0] == 'NAME_FIELD':
            field_ = t[1]
            androconf.debug("Found corresponding field: %s in source file: %s" % (field_, self.current_filename))
        else:
            self.mainwin.showStatus("Rename not available. Info ok: '%s' but object not supported." % selection)
            return

        rwin = RenameDialog(parent=self, win=self.mainwin, element=selection, info=(start, end))
        rwin.show()

    def actionGoto(self):
        cursor = self.textCursor()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        selection = cursor.selectedText()
        androconf.debug("Goto asked for '%s' (%d, %d)" % (selection, start, end))

        if start not in self.doc.binding.keys():
            self.mainwin.showStatus("Goto not available. No info for: '%s'." % selection)
            return

        t = self.doc.binding[start]
        if t[0] == 'NAME_METHOD_INVOKE':
            class_, method_ = t[2].split(' -> ')
            if class_ == 'this':
                class_ = self.path
            else:
                class_ = classdot2class(class_)
        else:
            self.mainwin.showStatus("Goto not available. Info ok: '%s' but object not supported." % selection)
            return

        androconf.debug("Found corresponding method: %s -> %s in source file: %s" % (class_, method_, self.path))

        if not self.mainwin.doesClassExist(class_):
            self.mainwin.showStatus("Goto not available. Class: %s not in database." % class_)
            return

        self.mainwin.openSourceWindow(class_, method=method_)

    def actionInfo(self):
        cursor = self.textCursor()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        androconf.debug("actionInfo asked for (%d, %d)" % (start, end))

        if start in self.doc.binding.keys():
            self.mainwin.showStatus('%s at position: (%d, %d)' % (str(self.doc.binding[start]), start, end))
        else:
            self.mainwin.showStatus("No info available.")

    def method_name_exist(self, meth_name):
        '''Check if there is already a meth_name method in the current class
           It is useful before allowing to rename a method to check name does
           not already exist.
        '''

        methods = self.current_class.get_methods()
        for m in methods:
            if m.name == meth_name:
                return True
        return False

    def field_name_exist(self, field_name):
        '''Check if there is already a field_name field in the current class
           It is useful before allowing to rename a field to check name does
           not already exist.
        '''

        fields = self.class_item.get_fields()
        for f in fields:
            if f.name == field_name:
                return True
        return False

    def renameElement(self, oldname, newname, info):
        '''Called back after a user chose a new name for an element.
        '''

        androconf.debug("Renaming %s into %s in %s" % (oldname, newname, self.current_filename))
        start, end = info
        try:
            t = self.doc.binding[start]
        except:
            self.mainwin.showStatus("Unexpected error in renameElement")
            return

        # Determine type of the to-be-renamed element and Androguard internal objects
        type_ = None
        if t[0] == 'NAME_METHOD_PROTOTYPE': # method definition in a class
            method_ = t[1]
            if method_ == self.title:
                method_ = 'init'

            proto_ = t[2].method.proto
            androconf.debug("Found: class=%s, method=%s, proto=%s" % (self.current_class, method_, proto_))
            type_ = "METHOD"
        elif t[0] == 'NAME_METHOD_INVOKE': # method call in a method
            class_, method_ = t[2].split(' -> ')
            class_ = classdot2class(class_)
            if class_ == 'this':
                class_ = self.path
            proto_ = proto2methodprotofunc("".join(t[3]) + t[4])
            androconf.debug("Found: class=%s, method=%s, proto=%s" % (class_, method_, proto_))
            type_ = "METHOD"
        elif t[0] == 'NAME_PROTOTYPE': # class definition on top of a class
            class_ = t[2] + '.' + t[1]
            package_ = t[2]
            androconf.debug("Found: package=%s, class=%s" % (package_, class_))
            type_ = "CLASS"
        elif t[0] == 'NAME_FIELD':
            field_item = t[3]
            type_ = "FIELD"
        else:
            self.mainwin.showStatus("Rename not available. Info found: '%s' but object not supported." % selection)
            return

        # Do the actual renaming
        if type_ == "METHOD":
            if self.method_name_exist(newname):
                self.mainwin.showStatus("Method name already exist")
                return

            method_class_name = self.current_class.get_name()
            method_name = method_
            method_proto = proto_
            current_analysis = self.session.get_analysis(self.current_class)


            method_item = current_analysis.get_method_by_name(method_class_name, method_name, method_proto)
            if not method_item:
                self.mainwin.showStatus("Impossible to find the method")
                return

            method_item.set_name(str(newname)) #unicode to ascii
        elif type_ == "CLASS":
            newname_class = classdot2class(package_ + '.' + newname)
            self.mainwin.showStatus("New name: %s" % newname_class)
            class_item = self.current_class #getattr(self.mainwin.d, classdot2func(class_))
            class_item.set_name(str(newname_class)) #unicode to ascii
            self.mainwin.updateDockWithTree()
        elif type_ == 'FIELD':
            if self.field_name_exist(newname):
                self.mainwin.showStatus("Field name already exist")
                return
            field_item.set_name(str(newname))
        else:
            self.mainwin.showStatus("Unsupported type: %s" % str(type_))
            return
        self.reload_java_sources()
