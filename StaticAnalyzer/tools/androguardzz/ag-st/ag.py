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


import sublime
import sublime_plugin

import os
import threading
import hashlib


from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.core.analysis import ganalysis
from androguard.decompiler import decompiler
from androguard.core import androconf

AG_DEX_VIEW = {}
AG_APK_VIEW = {}

AG_DEX_VIEW_LINK = {}
AG_REVERT_METHODS = {}
AG_REVERT_FIELDS = {}
AG_SC = {}
AG_METHOD_ID = {}
AG_FIELD_ID = {}
AG_CLASS_ID = {}
AG_AXML_ID = {}
AG_ARSC_ID = {}


AG_METHODS_LINE = {}
AG_FIELDS_LINE = {}
AG_CLASSES_LINE = {}

FILENAMES = {}


def get_setting(key, default=None):
    return sublime.load_settings("ag.sublime-settings").get(key, default)


def is_setting(key):
    return sublime.load_settings("ag.sublime-settings").has(key)


def get_params_info(nb, proto):
    i_buffer = "# Parameters:\n"

    ret = proto.split(')')
    params = ret[0][1:].split()
    if params:
        i_buffer += "# - local registers: v%d...v%d\n" % (0, nb - len(params) - 1)
        j = 0
        for i in xrange(nb - len(params), nb):
            i_buffer += "# - v%d:%s\n" % (i, dvm.get_type(params[j]))
            j += 1
    else:
        i_buffer += "# local registers: v%d...v%d\n" % (0, nb - 1)

    i_buffer += "#\n# - return:%s\n\n" % dvm.get_type(ret[1])

    return i_buffer


def get_bytecodes_class(dex_object, ana_object, class_obj):
    i_buffer = ""

    for i in class_obj.get_methods():
        i_buffer += get_bytecodes_method(dex_object, ana_object, i)

    return i_buffer


def get_bytecodes_method(dex_object, ana_object, method):
    mx = ana_object.get_method(method)

    basic_blocks = mx.basic_blocks.gets()
    i_buffer = ""

    idx = 0
    nb = 0

    i_buffer += "# %s->%s%s [access_flags=%s]\n#\n" % (method.get_class_name(), method.get_name(), method.get_descriptor(), method.get_access_flags_string())
    if method.code != None:
        i_buffer += get_params_info(method.code.get_registers_size(), method.get_descriptor())

        for i in basic_blocks:
            bb_buffer = ""
            ins_buffer = ""

            bb_buffer += "%s : " % (i.name)

            instructions = i.get_instructions()
            for ins in instructions:
                ins_buffer += "\t%-8d(%08x) " % (nb, idx)
                ins_buffer += "%-20s %s" % (ins.get_name(), ins.get_output(idx))

                op_value = ins.get_op_value()
                if ins == instructions[-1] and i.childs != []:
                    # packed/sparse-switch
                    if (op_value == 0x2b or op_value == 0x2c) and len(i.childs) > 1:
                          values = i.get_special_ins(idx).get_values()
                          bb_buffer += "[ D:%s " % (i.childs[0][2].name)
                          bb_buffer += ' '.join("%d:%s" % (values[j], i.childs[j + 1][2].name) for j in range(0, len(i.childs) - 1)) + " ]"
                    else:
                        #if len(i.childs) == 2:
                        #    i_buffer += "%s[ %s%s " % (branch_false_color, i.childs[0][2].name, branch_true_color))
                        #    print_fct(' '.join("%s" % c[2].name for c in i.childs[1:]) + " ]%s" % normal_color)
                        #else :
                        bb_buffer += "[ " + ' '.join("%s" % c[2].name for c in i.childs) + " ]"

                idx += ins.get_length()
                nb += 1

                ins_buffer += "\n"

            if i.get_exception_analysis() != None:
              ins_buffer += "\t%s\n" % (i.exception_analysis.show_buff())

            i_buffer += bb_buffer + "\n" + ins_buffer + "\n"

    return i_buffer


def get_field_info(field):
    i_buffer = ""

    i_buffer += "# %s->%s %s [access_flags=%s]\n#\n" % (field.get_class_name(), field.get_name(), field.get_descriptor(), field.get_access_flags_string())

    init_value = field.get_init_value()
    if init_value != None:
        i_buffer += repr(str(init_value.get_value()))

    return i_buffer


def get_axml_info(apk_object):
    i_buffer = "PERMISSIONS:\n"
    details_permissions = apk_object.get_details_permissions()
    for i in details_permissions:
        i_buffer += "\t%s %s\n" % (i, details_permissions[i])
    i_buffer += "\nMAIN ACTIVITY: %s\n" % apk_object.get_main_activity()

    i_buffer += "\nACTIVITIES:\n"
    for i in apk_object.get_activities():
        i_buffer += "\t%s\n" % (i)

    i_buffer += "\nSERVICES:\n"
    for i in apk_object.get_services():
        i_buffer += "\t%s\n" % (i)

    i_buffer += "\nRECEIVERS:\n"
    for i in apk_object.get_receivers():
        i_buffer += "\t%s\n" % (i)

    i_buffer += "\nPROVIDERS:\n"
    for i in apk_object.get_providers():
        i_buffer += "\t%s\n" % (i)

    return i_buffer


def get_arsc_info(arscobj):
    buff = ""
    for package in arscobj.get_packages_names():
        buff += package + ":\n"
        for locale in arscobj.get_locales(package):
            buff += "\t" + repr(locale) + ":\n"
            for ttype in arscobj.get_types(package, locale):
                buff += "\t\t" + ttype + ":\n"
                try:
                    tmp_buff = getattr(arscobj, "get_" + ttype + "_resources")(package, locale).decode("utf-8", 'replace').split("\n")
                    for i in tmp_buff:
                        buff += "\t\t\t" + i + "\n"
                except AttributeError:
                    pass

    return buff


def get_sourcecode_method(dex_object, ana_object, method):
    return method.get_source()


class MethodView:
    def __init__(self, orig_id, method):
        self.view = sublime.active_window().new_file()
        self.dex_object, self.ana_object = AG_DEX_VIEW[orig_id]
        AG_DEX_VIEW_LINK[self.view.id()] = orig_id
        AG_REVERT_METHODS[method] = self.view

        self.view.set_name("%s-%s-%s.mag" % (method.get_class_name(), method.get_name(), method.get_descriptor()))
        self.view.set_syntax_file("Packages/ag-st/agbytecodes.tmLanguage")

        self.view.set_scratch(True)
        edit = self.view.begin_edit()

        i_buffer = get_bytecodes_method(self.dex_object, self.ana_object, method)
        AG_METHOD_ID[self.view.id()] = method

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.sel().clear()

        if self.view.id() not in AG_SC:
            AG_SC[self.view.id()] = False


class FieldView:
    def __init__(self, orig_id, field):
        self.view = sublime.active_window().new_file()
        self.dex_object, self.ana_object = AG_DEX_VIEW[orig_id]
        AG_DEX_VIEW_LINK[self.view.id()] = orig_id
        AG_REVERT_FIELDS[field] = self.view

        self.view.set_name("%s-%s-%s.fag" % (field.get_class_name(), field.get_name(), field.get_descriptor()))
        self.view.set_syntax_file("Packages/ag-st/agbytecodes.tmLanguage")

        self.view.set_scratch(True)
        edit = self.view.begin_edit()

        i_buffer = get_field_info(field)
        AG_FIELD_ID[self.view.id()] = field

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.sel().clear()


class ClassView:
    def __init__(self, orig_id, class_obj):
        self.view = sublime.active_window().new_file()
        self.dex_object, self.ana_object = AG_DEX_VIEW[orig_id]
        AG_DEX_VIEW_LINK[self.view.id()] = orig_id

        self.view.set_name("%s.cag" % (class_obj.get_name()))
        self.view.set_syntax_file("Packages/ag-st/agbytecodes.tmLanguage")

        self.view.set_scratch(True)
        edit = self.view.begin_edit()

        i_buffer = get_bytecodes_class(self.dex_object, self.ana_object, class_obj)

        AG_CLASS_ID[self.view.id()] = class_obj

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.sel().clear()

        if self.view.id() not in AG_SC:
            AG_SC[self.view.id()] = False


class AgDoubleClick(sublime_plugin.TextCommand):
    def extract_bb(self, raw, position):
        raw_list = raw.split(" ")
        idx = 0
        for i in raw_list:
            begin = idx
            end = idx + len(i)

            if position >= begin and position <= end:
                if ":" in i:
                    return i.split(":")[-1]
                return i
            idx += len(i)
        return None

    def run(self, edit):
        if self.view.id() in AG_METHOD_ID and self.view.id() in AG_SC:
            if not AG_SC[self.view.id()]:
                for sel in self.view.sel():
                    if self.view.scope_name(sel.begin()) == 'source.agbt markup.list ':
                        scope_region = self.view.extract_scope(sel.begin())

                        scope_value = self.view.substr(scope_region)

                        bb_selected = self.extract_bb(scope_value, sel.begin() - scope_region.begin())
                        region_bb = self.view.find("^(%s)" % bb_selected, 0)
                        self.view.run_command("goto_line", {"line": self.view.rowcol(region_bb.end())[0] + 1})

        if self.view.id() in AG_DEX_VIEW:
            current_view_id = self.view.id()
            datas = []
            try:
                for sel in self.view.sel():
                    x, y = self.view.rowcol(sel.begin())
                    datas.append(x)
            except AttributeError:
                pass

            dex_object, ana_object = AG_DEX_VIEW[self.view.id()]

            for x in datas:
                if x in AG_METHODS_LINE[current_view_id]:
                    MethodView(self.view.id(), AG_METHODS_LINE[current_view_id][x])
                elif x in AG_FIELDS_LINE[current_view_id]:
                    FieldView(self.view.id(), AG_FIELDS_LINE[current_view_id][x])
                elif x in AG_CLASSES_LINE[current_view_id]:
                    ClassView(self.view.id(), AG_CLASSES_LINE[current_view_id][x])

        elif self.view.id() in AG_APK_VIEW:
            apk_object = AG_APK_VIEW[self.view.id()]

            datas = []
            try:
                for sel in self.view.sel():
                    datas.append(self.view.substr(self.view.line(sel)))
            except AttributeError:
                pass

            filename = FILENAMES[self.view.id()]
            for x in datas:
                if x == "classes.dex":
                    at = AnalyseDexThread(sublime.active_window().new_file(), filename + "-classes", apk_object.get_dex())
                    at.run()
                elif x == "AndroidManifest.xml":
                    at = AnalyseAXMLThread(sublime.active_window().new_file(), filename + "-AndroidManifest", apk_object)
                    at.run()
                elif x == "resources.arsc":
                    at = AnalyseARSCThread(sublime.active_window().new_file(), filename + "-resources", apk_object.get_file(x))
                    at.run()
                elif ".xml" in x:
                    at = AnalyseAXMLSimpleThread(sublime.active_window().new_file(), filename + "-%s" + x, apk_object.get_file(x))
                    at.run()
                else:
                    new_view = sublime.active_window().new_file()
                    new_view.set_name("%s-%s" % (filename, x))
                    new_view.set_syntax_file("Packages/Text/Plain text.tmLanguage")

                    new_view.set_scratch(True)
                    edit = new_view.begin_edit()
                    new_view.sel().clear()

                    i_buffer = apk_object.get_file(x).decode('utf-8', 'replace')

                    new_view.replace(edit, sublime.Region(0, new_view.size()), i_buffer)
                    new_view.end_edit(edit)
                    new_view.set_read_only(True)


class ThreadProgress():
    def __init__(self, thread, message, success_message):
        self.thread = thread
        self.message = message
        self.success_message = success_message
        self.addend = 1
        self.size = 8
        sublime.set_timeout(lambda: self.run(0), 100)

    def run(self, i):
        if not self.thread.is_alive():
            if hasattr(self.thread, 'result') and not self.thread.result:
                sublime.status_message('')
                return
            sublime.status_message(self.success_message)
            return

        before = i % self.size
        after = (self.size - 1) - before
        sublime.status_message('%s [%s=%s]' % \
            (self.message, ' ' * before, ' ' * after))
        if not after:
            self.addend = -1
        if not before:
            self.addend = 1
        i += self.addend
        sublime.set_timeout(lambda: self.run(i), 100)


class AnalyseAXMLThread:
    def __init__(self, view, filename, apk_object):
        self.view = view
        self.apk_object = apk_object
        self.filename = filename
        #threading.Thread.__init__(self)

    def run(self):
        self.view.set_name("%s.uaxml" % (self.filename))

        self.view.set_scratch(True)
        edit = self.view.begin_edit()
        self.view.sel().clear()
        #self.view.set_syntax_file("Packages/ag-st/agapk.tmLanguage")

        i_buffer = get_axml_info(self.apk_object)

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.set_read_only(True)

        AG_AXML_ID[self.view.id()] = self.apk_object

        if self.view.id() not in AG_SC:
            AG_SC[self.view.id()] = False


class AnalyseAXMLSimpleThread:
    def __init__(self, view, filename, raw_object):
        self.view = view
        self.raw_object = raw_object
        self.filename = filename
        #threading.Thread.__init__(self)

    def run(self):
        self.view.set_name("%s.uaxml" % (self.filename))

        self.view.set_scratch(True)
        edit = self.view.begin_edit()
        self.view.sel().clear()
        self.view.set_syntax_file("Packages/XML/XML.tmLanguage")

        ap = apk.AXMLPrinter(self.raw_object)
        i_buffer = ap.get_xml()

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.set_read_only(True)


class AnalyseARSCThread:
    def __init__(self, view, filename, raw_object):
        self.view = view
        self.raw_object = raw_object
        self.filename = filename
        #threading.Thread.__init__(self)

    def run(self):
        self.view.set_name("%s.uarsc" % (self.filename))

        self.view.set_scratch(True)
        edit = self.view.begin_edit()
        self.view.sel().clear()
        #self.view.set_syntax_file("Packages/ag-st/agapk.tmLanguage")

        arscobj = apk.ARSCParser(self.raw_object)
        i_buffer = get_arsc_info(arscobj)

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.set_read_only(True)

        AG_ARSC_ID[self.view.id()] = arscobj

        if self.view.id() not in AG_SC:
            AG_SC[self.view.id()] = False


class AnalyseAPKThread:
    def __init__(self, view, filename, raw):
        self.view = view
        self.raw = raw
        self.filename = filename
        #threading.Thread.__init__(self)

    def run(self):
        apk_object = apk.APK(self.raw, raw=True)
        self.view.set_name("%s.uapk" % (self.filename))

        self.view.set_scratch(True)
        edit = self.view.begin_edit()
        self.view.sel().clear()
        self.view.set_syntax_file("Packages/ag-st/agapk.tmLanguage")

        i_buffer = ""
#        files_list = apk_object.get_files_types()
#        for i in files_list:
#            i_buffer += "%s: %s" % (i, files_list[i])

        for i in sorted(apk_object.get_files()):
            i_buffer += "%s\n" % i

        self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
        self.view.end_edit(edit)
        self.view.set_read_only(True)
        AG_APK_VIEW[self.view.id()] = apk_object
        FILENAMES[self.view.id()] = hashlib.sha1(apk_object.get_raw()).hexdigest()


class AnalyseDexThread:  # (threading.Thread):
    def __init__(self, view, filename, raw):
        self.view = view
        self.raw = raw
        self.filename = filename
        #threading.Thread.__init__(self)

    def run(self):
        if androconf.is_android_raw(self.raw) == "DEY":
            dex_object = dvm.DalvikOdexVMFormat(self.raw)
        else:
            dex_object = dvm.DalvikVMFormat(self.raw)

        ana_object = analysis.uVMAnalysis(dex_object)
        gvm_object = ganalysis.GVMAnalysis(ana_object, None)

        dex_object.set_vmanalysis(ana_object)
        dex_object.set_gvmanalysis(gvm_object)

        for i in androconf.CONF:
            if is_setting(i):
                androconf.CONF[i] = get_setting(i)

        decompiler_option = get_setting("DEFAULT_DECOMPILER", "dad")

        if decompiler_option == "dex2jad":
            dex_object.set_decompiler(decompiler.DecompilerDex2Jad(
                dex_object,
                androconf.CONF["PATH_DEX2JAR"],
                androconf.CONF["BIN_DEX2JAR"],
                androconf.CONF["PATH_JAD"],
                androconf.CONF["BIN_JAD"],
                androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_option == "ded":
            dex_object.set_decompiler(decompiler.DecompilerDed(
                dex_object,
                androconf.CONF["PATH_DED"],
                androconf.CONF["BIN_DED"],
                androconf.CONF["TMP_DIRECTORY"]))
        else:
            dex_object.set_decompiler(decompiler.DecompilerDAD(dex_object, ana_object))

        dex_object.create_xref()
        dex_object.create_dref()

        self.view.set_name("%s.ag" % (self.filename))

        self.view.set_scratch(True)
        edit = self.view.begin_edit()
        self.view.sel().clear()
        self.view.set_syntax_file("Packages/ag-st/ag.tmLanguage")

        by_package = {}
        for current_class in dex_object.get_classes():
          name = current_class.get_name()

          try:
            by_package[os.path.dirname(name)].append(current_class)
          except KeyError:
            by_package[os.path.dirname(name)] = []
            by_package[os.path.dirname(name)].append(current_class)

        b_buffer = ""
        line = 0

        AG_METHODS_LINE[self.view.id()] = {}
        AG_CLASSES_LINE[self.view.id()] = {}
        AG_FIELDS_LINE[self.view.id()] = {}
        for key in sorted(by_package.iterkeys()):
            b_buffer += "%s\n" % key
            line += 1

            for c_class in sorted(by_package[key], key=lambda k: k.get_name()):
                b_buffer += "\t%s extends %s\n" % (c_class.get_name()[1:-1], c_class.get_superclassname()[1:-1])
                AG_CLASSES_LINE[self.view.id()][line] = c_class
                line += 1

                for j in c_class.get_methods():
                    b_buffer += "\t\tmethod: %s %s [%s] size:%d\n" % (j.get_name(), j.get_descriptor(), j.get_access_flags_string(), j.get_length())
                    AG_METHODS_LINE[self.view.id()][line] = j
                    line += 1

                b_buffer += "\n"
                line += 1

                for j in c_class.get_fields():
                    b_buffer += "\t\tfield: %s %s [%s %s]" % (j.get_name(), j.get_descriptor(), j.get_access_flags_string(), dvm.get_type(j.get_descriptor()))

                    init_value = j.get_init_value()
                    if init_value != None:
                        b_buffer += " (%s)" % repr(str(init_value.get_value()))
                    b_buffer += "\n"

                    AG_FIELDS_LINE[self.view.id()][line] = j
                    line += 1

                b_buffer += "\n"
                line += 1

        l = dex_object.get_classes_hierarchy()
        h_buffer = ""
        for i in l:
            h_buffer += i + "\n"

        b_buffer += h_buffer

        self.view.replace(edit, sublime.Region(0, self.view.size()), b_buffer)
        self.view.end_edit(edit)
        self.view.set_read_only(True)
        AG_DEX_VIEW[self.view.id()] = (dex_object, ana_object)
        FILENAMES[self.view.id()] = hashlib.sha1(dex_object.get_buff()).hexdigest()


class AgCommand(sublime_plugin.WindowCommand):
  def run(self):
    self.view = self.window.active_view()

    filename = self.view.file_name()

    ret = androconf.is_android(filename)
    if ret == "APK":
        at = AnalyseAPKThread(self.window.new_file(), filename, open(filename, "rb").read())
        at.run()
    elif ret == "DEX" or ret == "DEY":
        at = AnalyseDexThread(self.window.new_file(), filename, open(filename, "rb").read())
        at.run()
    elif ret == "AXML":
        at = AnalyseAXMLSimpleThread(self.window.new_file(), filename, open(filename, "rb").read())
        at.run()
    elif ret == "ARSC":
        at = AnalyseARSCThread(self.window.new_file(), filename, open(filename, "rb").read())
        at.run()

    #thread = AnalyseThread(self.window.new_file(), filename, open(filename, "rb").read())
    #thread.start()
    #ThreadProgress(thread,
    #               "Analysing app ...",
    #               "Finished !")


def get_strings_info(dex_object, ana_object):
    i_buffer = ""

    for i in dex_object.get_strings():
        i_buffer += repr(i) + "\n"
        if ana_object != None:
            ref = ana_object.tainted_variables.get_string(i)
            if ref != None:
                for path in ref.get_paths():
                    access, idx = path[0]
                    m_idx = path[1]
                    method = dex_object.get_cm_method(m_idx)
                    i_buffer += "\t\t%s %x %s->%s %s\n" % (access, idx, method[0], method[1], method[2][0] + method[2][1])

    return i_buffer


class AgStrings(sublime_plugin.WindowCommand):
  def run(self):
    self.view = self.window.active_view()
    if self.view.id() in AG_DEX_VIEW:
        dex_object, ana_object = AG_DEX_VIEW[self.view.id()]

        view = sublime.active_window().new_file()

        filename = FILENAMES[self.view.id()]
        view.set_name("%s.strings" % filename)

        view.set_scratch(True)
        edit = view.begin_edit()

        i_buffer = get_strings_info(dex_object, ana_object)

        view.replace(edit, sublime.Region(0, view.size()), i_buffer)
        view.end_edit(edit)
        view.sel().clear()


class AgTrCommand(sublime_plugin.WindowCommand):
    def run(self):
        self.view = self.window.active_view()

        if self.view.id() in AG_METHOD_ID:
            dex_object, ana_object = AG_DEX_VIEW[AG_DEX_VIEW_LINK[self.view.id()]]

            self.view.sel().clear()
            if not AG_SC[self.view.id()]:
                self.view.set_syntax_file("Packages/Java/Java.tmLanguage")
                i_buffer = get_sourcecode_method(dex_object, ana_object, AG_METHOD_ID[self.view.id()])
            else:
                self.view.set_syntax_file("Packages/ag-st/agbytecodes.tmLanguage")
                i_buffer = get_bytecodes_method(dex_object, ana_object, AG_METHOD_ID[self.view.id()])

            self.view.set_read_only(False)
            edit = self.view.begin_edit()
            self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
            self.view.end_edit(edit)
            AG_SC[self.view.id()] = not AG_SC[self.view.id()]

        elif self.view.id() in AG_CLASS_ID:
            dex_object, ana_object = AG_DEX_VIEW[AG_DEX_VIEW_LINK[self.view.id()]]

            self.view.sel().clear()

            if not AG_SC[self.view.id()]:
                self.view.set_syntax_file("Packages/Java/Java.tmLanguage")
                i_buffer = AG_CLASS_ID[self.view.id()].get_source()
            else:
                self.view.set_syntax_file("Packages/ag-st/agbytecodes.tmLanguage")
                i_buffer = get_bytecodes_class(dex_object, ana_object, AG_CLASS_ID[self.view.id()])

            self.view.set_read_only(False)
            edit = self.view.begin_edit()
            self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
            self.view.end_edit(edit)

            AG_SC[self.view.id()] = not AG_SC[self.view.id()]

        elif self.view.id() in AG_AXML_ID:
            apk_object = AG_AXML_ID[self.view.id()]

            self.view.sel().clear()

            if not AG_SC[self.view.id()]:
                i_buffer = apk_object.get_android_manifest_xml().toprettyxml()
                self.view.set_syntax_file("Packages/XML/XML.tmLanguage")
            else:
                i_buffer = get_axml_info(apk_object)

            self.view.set_read_only(False)
            edit = self.view.begin_edit()
            self.view.replace(edit, sublime.Region(0, self.view.size()), i_buffer)
            self.view.end_edit(edit)

            AG_SC[self.view.id()] = not AG_SC[self.view.id()]


class AgRefFromCommand(sublime_plugin.WindowCommand):
    def set_ref(self, value):
        if value == -1:
            return

        if self.view.id() in AG_METHOD_ID:
            self.set_ref_method(value, 0)
        elif self.view.id() in AG_FIELD_ID:
            self.set_ref_method(value, 1)

    def set_ref_method(self, value, action):
        if action == 0:
            method = AG_METHOD_ID[self.view.id()]
            x_method = method.XREFfrom.items[value][0]
        else:
            field = AG_FIELD_ID[self.view.id()]
            x_method = field.DREFr.items[value][0]

        if x_method in AG_REVERT_METHODS:
            if self.window.get_view_index(AG_REVERT_METHODS[x_method])[0] != -1:
                self.window.focus_view(AG_REVERT_METHODS[x_method])
            else:
                del AG_REVERT_METHODS[x_method]
                MethodView(AG_DEX_VIEW_LINK[self.view.id()], x_method)
        else:
            MethodView(AG_DEX_VIEW_LINK[self.view.id()], x_method)

    def run(self):
        self.option_list = []

        self.view = self.window.active_view()
        if self.view.id() in AG_METHOD_ID:
            method = AG_METHOD_ID[self.view.id()]
            for i in method.XREFfrom.items:
                x_method = i[0]
                self.option_list.append("%s %s %s" % (x_method.get_class_name(), x_method.get_name(), x_method.get_descriptor()))
        elif self.view.id() in AG_FIELD_ID:
            field = AG_FIELD_ID[self.view.id()]
            for i in field.DREFr.items:
                x_method = i[0]
                self.option_list.append("%s %s %s" % (x_method.get_class_name(), x_method.get_name(), x_method.get_descriptor()))

        self.window.show_quick_panel(self.option_list, self.set_ref)


class AgRefToCommand(sublime_plugin.WindowCommand):
    def set_ref(self, value):
        if value == -1:
            return

        if self.view.id() in AG_METHOD_ID:
            self.set_ref_method(value, 0)
        elif self.view.id() in AG_FIELD_ID:
            self.set_ref_method(value, 1)

    def set_ref_method(self, value, action):
        if action == 0:
            method = AG_METHOD_ID[self.view.id()]
            x_method = method.XREFto.items[value][0]
        else:
            field = AG_FIELD_ID[self.view.id()]
            x_method = field.DREFw.items[value][0]

        if x_method in AG_REVERT_METHODS:
                if self.window.get_view_index(AG_REVERT_METHODS[x_method])[0] != -1:
                    self.window.focus_view(AG_REVERT_METHODS[x_method])
                else:
                    del AG_REVERT_METHODS[x_method]
                    MethodView(AG_DEX_VIEW_LINK[self.view.id()], x_method)
        else:
            MethodView(AG_DEX_VIEW_LINK[self.view.id()], x_method)

    def run(self):
        self.option_list = []

        self.view = self.window.active_view()
        if self.view.id() in AG_METHOD_ID:
            method = AG_METHOD_ID[self.view.id()]
            for i in method.XREFto.items:
                x_method = i[0]
                self.option_list.append("%s %s %s" % (x_method.get_class_name(), x_method.get_name(), x_method.get_descriptor()))
        elif self.view.id() in AG_FIELD_ID:
            field = AG_FIELD_ID[self.view.id()]
            for i in field.DREFw.items:
                x_method = i[0]
                self.option_list.append("%s %s %s" % (x_method.get_class_name(), x_method.get_name(), x_method.get_descriptor()))

        self.window.show_quick_panel(self.option_list, self.set_ref)


class AgReset(sublime_plugin.WindowCommand):
  def run(self):
    self.view = self.window.active_view()

    global AG_DEX_VIEW
    global AG_APK_VIEW
    global AG_DEX_VIEW_LINK
    global AG_REVERT_METHODS
    global AG_REVERT_FIELDS
    global AG_SC
    global AG_METHOD_ID
    global AG_FIELD_ID
    global AG_CLASS_ID
    global AG_METHODS_LINE
    global AG_FIELDS_LINE
    global AG_CLASSES_LINE
    global AG_AXML_ID
    global AG_ARSC_ID

    AG_DEX_VIEW = {}
    AG_APK_VIEW = {}

    AG_DEX_VIEW_LINK = {}
    AG_REVERT_METHODS = {}
    AG_REVERT_FIELDS = {}
    AG_SC = {}
    AG_METHOD_ID = {}
    AG_FIELD_ID = {}
    AG_CLASS_ID = {}
    AG_AXML_ID = {}
    AG_ARSC_ID = {}

    AG_METHODS_LINE = {}
    AG_FIELDS_LINE = {}
    AG_CLASSES_LINE = {}

    print "Reset Androguard Plugin"
