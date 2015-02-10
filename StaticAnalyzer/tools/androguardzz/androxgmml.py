#!/usr/bin/env python

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

from xml.sax.saxutils import escape
import sys, os
from optparse import OptionParser

from androguard.core.androgen import Androguard
from androguard.core.analysis import analysis

option_0 = { 'name' : ('-i', '--input'), 'help' : 'filename input', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'filename output of the xgmml', 'nargs' : 1 }
option_2 = { 'name' : ('-f', '--functions'), 'help' : 'include function calls', 'action' : 'count' }
option_3 = { 'name' : ('-e', '--externals'), 'help' : 'include extern function calls', 'action' : 'count' }
option_4 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

METHODS_ID = {}
EXTERNAL_METHODS_ID = {}
NODES_ID = {}
EDGES_ID = {}

NODE_GRAPHIC = {
   "classic" : {
                 "h" : 20.0,
                 "w" : 20.0,
                 "type" : "ELLIPSE",
                 "width" : 1,
                 "fill" : "#e1e1e1",
                 "outline" : "#000000",
               },

   "extern" : {
                 "h" : 20.0,
                 "w" : 20.0,
                 "type" : "ELLIPSE",
                 "width" : 1,
                 "fill" : "#ff8c00",
                 "outline" : "#000000",
               }
}

EDGE_GRAPHIC = {
   "cfg" : {
               "width" : 2,
               "fill" : "#0000e1",
   },

   "fcg" : {
               "width" : 3,
               "fill" : "#9acd32",
   },

   "efcg" : {
               "width" : 3,
               "fill" : "#808000",
   }
}

def get_node_name(method, bb) :
    return "%s-%s-%s" % ( method.get_class_name(), escape(bb.name), escape(method.get_descriptor()) )

def export_xgmml_cfg(g, fd) :
    method = g.get_method()

    name = method.get_name()
    class_name = method.get_class_name()
    descriptor = method.get_descriptor()

    if method.get_code() != None :
        size_ins = method.get_code().get_length()

    for i in g.basic_blocks.get() :
        fd.write("<node id=\"%d\" label=\"%s\">\n" % (len(NODES_ID), get_node_name(method, i)))

        fd.write("<att type=\"string\" name=\"classname\" value=\"%s\"/>\n" % (escape(class_name)))
        fd.write("<att type=\"string\" name=\"name\" value=\"%s\"/>\n" % (escape(name)))
        fd.write("<att type=\"string\" name=\"descriptor\" value=\"%s\"/>\n" % (escape(descriptor)))

        fd.write("<att type=\"integer\" name=\"offset\" value=\"%d\"/>\n" % (i.start))

        cl = NODE_GRAPHIC["classic"]
        width = cl["width"]
        fill = cl["fill"]

        # No child ...
        if i.childs == [] :
            fill = "#87ceeb"

        if i.start == 0 :
            fd.write("<att type=\"string\" name=\"node.label\" value=\"%s\\n%s\"/>\n" % (escape(name), i.get_instructions()[-1].get_name()))
            width = 3
            fill = "#ff0000"

            METHODS_ID[ class_name + name + descriptor ] = len(NODES_ID)
        else :
            fd.write("<att type=\"string\" name=\"node.label\" value=\"0x%x\\n%s\"/>\n" % (i.start, i.get_instructions()[-1].get_name()))

        size = 0
        for tmp_ins in i.get_instructions() :
            size += (tmp_ins.get_length() / 2)


        h = ((size / float(size_ins)) * 20) + cl["h"]

        fd.write("<graphics type=\"%s\" h=\"%.1f\" w=\"%.1f\" width=\"%d\" fill=\"%s\" outline=\"%s\">\n" % ( cl["type"], h, h, width, fill, cl["outline"]))
        fd.write("</graphics>\n")

        fd.write("</node>\n")

        NODES_ID[ class_name + i.name + descriptor ] = len(NODES_ID)

    for i in g.basic_blocks.get() :
        for j in i.childs :
            if j[-1] != None :
                label = "%s (cfg) %s" % (get_node_name(method, i), get_node_name(method, j[-1]))
                id = len(NODES_ID) + len(EDGES_ID)
                fd.write( "<edge id=\"%d\" label=\"%s\" source=\"%d\" target=\"%d\">\n" % (id, label, NODES_ID[ class_name + i.name + descriptor ], NODES_ID[ class_name + j[-1].name + descriptor ]) )

                cl = EDGE_GRAPHIC["cfg"]
                fd.write("<graphics width=\"%d\" fill=\"%s\">\n" % (cl["width"], cl["fill"]) )
                fd.write("</graphics>\n")

                fd.write("</edge>\n")

                EDGES_ID[ label ] = id

def export_xgmml_fcg(a, x, fd) :
    classes = a.get_classes_names()

    # Methods flow graph
    for m, _ in x.get_tainted_packages().get_packages() :
        paths = m.get_methods()
        for j in paths :
            if j.get_method().get_class_name() in classes and m.get_info() in classes :
                if j.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
                    t =  m.get_info() + j.get_name() + j.get_descriptor()
                    if t not in METHODS_ID :
                        continue

                    bb1 = x.get_method( j.get_method() ).basic_blocks.get_basic_block( j.get_idx() )

                    node1 = get_node_name(j.get_method(), bb1) + "@0x%x" % j.get_idx()
                    node2 = "%s-%s-%s" % (m.get_info(), escape(j.get_name()), escape(j.get_descriptor()))

                    label = "%s (fcg) %s" % (node1, node2)

                    if label in EDGES_ID :
                        continue

                    id = len(NODES_ID) + len(EDGES_ID)

                    fd.write( "<edge id=\"%d\" label=\"%s\" source=\"%d\" target=\"%d\">\n" % (id,
                                                                                               label,
                                                                                               NODES_ID[ j.get_method().get_class_name() + bb1.name + j.get_method().get_descriptor() ],
                                                                                               METHODS_ID[ m.get_info() + j.get_name() + j.get_descriptor() ]) )

                    cl = EDGE_GRAPHIC["fcg"]
                    fd.write("<graphics width=\"%d\" fill=\"%s\">\n" % (cl["width"], cl["fill"]) )
                    fd.write("</graphics>\n")

                    fd.write("</edge>\n")

                    EDGES_ID[ label ] = id

def export_xgmml_efcg(a, x, fd) :
    classes = a.get_classes_names()

    # Methods flow graph
    for m, _ in x.get_tainted_packages().get_packages() :
        paths = m.get_methods()
        for j in paths :
            if j.get_method().get_class_name() in classes and m.get_info() not in classes :
                if j.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
                    t =  m.get_info() + j.get_name() + j.get_descriptor()
                    if t not in EXTERNAL_METHODS_ID :
                        fd.write("<node id=\"%d\" label=\"%s\">\n" % (len(NODES_ID), escape(t)))

                        fd.write("<att type=\"string\" name=\"classname\" value=\"%s\"/>\n" % (escape(m.get_info())))
                        fd.write("<att type=\"string\" name=\"name\" value=\"%s\"/>\n" % (escape(j.get_name())))
                        fd.write("<att type=\"string\" name=\"descriptor\" value=\"%s\"/>\n" % (escape(j.get_descriptor())))

                        cl = NODE_GRAPHIC["extern"]

                        fd.write("<att type=\"string\" name=\"node.label\" value=\"%s\\n%s\\n%s\"/>\n" % (escape(m.get_info()), escape(j.get_name()), escape(j.get_descriptor())))

                        fd.write("<graphics type=\"%s\" h=\"%.1f\" w=\"%.1f\" width=\"%d\" fill=\"%s\" outline=\"%s\">\n" % ( cl["type"], cl["h"], cl["h"], cl["width"], cl["fill"], cl["outline"]))
                        fd.write("</graphics>\n")

                        fd.write("</node>\n")

                        NODES_ID[ t ] = len(NODES_ID)
                        EXTERNAL_METHODS_ID[ t ] = NODES_ID[ t ]

                    bb1 = x.get_method( j.get_method() ).basic_blocks.get_basic_block( j.get_idx() )

                    node1 = get_node_name(j.get_method(), bb1) + "@0x%x" % j.get_idx()
                    node2 = "%s-%s-%s" % (m.get_info(), escape(j.get_name()), escape(j.get_descriptor()))

                    label = "%s (efcg) %s" % (node1, node2)

                    if label in EDGES_ID :
                        continue

                    id = len(NODES_ID) + len(EDGES_ID)

                    fd.write( "<edge id=\"%d\" label=\"%s\" source=\"%d\" target=\"%d\">\n" % (id,
                                                                                               label,
                                                                                               NODES_ID[ j.get_method().get_class_name() + bb1.name + j.get_method().get_descriptor() ],
                                                                                               EXTERNAL_METHODS_ID[ m.get_info() + j.get_name() + j.get_descriptor() ]) )

                    cl = EDGE_GRAPHIC["efcg"]
                    fd.write("<graphics width=\"%d\" fill=\"%s\">\n" % (cl["width"], cl["fill"]) )
                    fd.write("</graphics>\n")

                    fd.write("</edge>\n")

                    EDGES_ID[ label ] = id

def export_apps_to_xgmml( input, output, fcg, efcg ) :
    a = Androguard( [ input ] )

    fd = open(output, "w")
    fd.write("<?xml version='1.0'?>\n")
    fd.write("<graph label=\"Androguard XGMML %s\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:ns1=\"http://www.w3.org/1999/xlink\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" xmlns=\"http://www.cs.rpi.edu/XGMML\" directed=\"1\">\n" % (os.path.basename(input)))

    for vm in a.get_vms() :
        x = analysis.VMAnalysis( vm )
        # CFG
        for method in vm.get_methods() :
            g = x.get_method( method )
            export_xgmml_cfg(g, fd)

        if fcg :
            export_xgmml_fcg(vm, x, fd)

        if efcg :
            export_xgmml_efcg(vm, x, fd)

    fd.write("</graph>")
    fd.close()

def main(options, arguments) :
    if options.input != None and options.output != None :
        export_apps_to_xgmml( options.input, options.output, options.functions, options.externals )

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)


    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
