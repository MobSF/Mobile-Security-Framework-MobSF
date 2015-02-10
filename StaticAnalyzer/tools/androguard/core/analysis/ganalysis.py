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

from networkx import DiGraph
from xml.sax.saxutils import escape

from androguard.core import bytecode
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS
from androguard.core.analysis.risk import PERMISSIONS_RISK, INTERNET_RISK, PRIVACY_RISK, PHONE_RISK, SMS_RISK, MONEY_RISK
from androguard.core.analysis.analysis import TAINTED_PACKAGE_CREATE

DEFAULT_RISKS = {
    INTERNET_RISK : ( "INTERNET_RISK", (195, 255, 0) ),
    PRIVACY_RISK : ( "PRIVACY_RISK", (255, 255, 51) ),
    PHONE_RISK : ( "PHONE_RISK", ( 255, 216, 0 ) ),
    SMS_RISK : ( "SMS_RISK", ( 255, 93, 0 ) ),
    MONEY_RISK : ( "MONEY_RISK", ( 255, 0, 0 ) ),
}

DEXCLASSLOADER_COLOR = (0, 0, 0)
ACTIVITY_COLOR = (51, 255, 51)
SERVICE_COLOR = (0, 204, 204)
RECEIVER_COLOR = (204, 51, 204)

ID_ATTRIBUTES = {
    "type" : 0,
    "class_name" : 1,
    "method_name" : 2,
    "descriptor" : 3,
    "permissions" : 4,
    "permissions_level" : 5,
    "dynamic_code" : 6,
}

class GVMAnalysis :
    def __init__(self, vmx, apk) :
        self.vmx = vmx
        self.vm = self.vmx.get_vm()

        self.nodes = {}
        self.nodes_id = {}
        self.entry_nodes = [] 
        self.G = DiGraph()

        for j in self.vmx.get_tainted_packages().get_internal_packages() :
            n1 = self._get_node( j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor() )
            n2 = self._get_node( j.get_class_name(), j.get_name(), j.get_descriptor() )

            self.G.add_edge( n1.id, n2.id )
            n1.add_edge( n2, j )
        #    print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
        #                                            j.get_bb().start + j.get_idx(), \
        #                                            j.get_class_name(), j.get_name(), j.get_descriptor())

        if apk != None :
            for i in apk.get_activities() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "(Landroid/os/Bundle;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "activity" } )
                    n1.set_attributes( { "color" : ACTIVITY_COLOR } )
                    n2 = self._get_new_node_from( n1, "ACTIVITY" )
                    n2.set_attributes( { "color" : ACTIVITY_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_services() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "()V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "service" } )
                    n1.set_attributes( { "color" : SERVICE_COLOR } )
                    n2 = self._get_new_node_from( n1, "SERVICE" )
                    n2.set_attributes( { "color" : SERVICE_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_receivers() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onReceive", "(Landroid/content/Context; Landroid/content/Intent;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "receiver" } )
                    n1.set_attributes( { "color" : RECEIVER_COLOR } )
                    n2 = self._get_new_node_from( n1, "RECEIVER" )
                    n2.set_attributes( { "color" : RECEIVER_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )

        # Specific Java/Android library
        for c in self.vm.get_classes() :
            #if c.get_superclassname() == "Landroid/app/Service;" :
            #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
            #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )

            #    self.G.add_edge( n1.id, n2.id )
            if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
                for i in self.vm.get_method("run") :
                    if i.get_class_name() == c.get_name() :
                        n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
                        n2 = self._get_node( i.get_class_name(), "start", i.get_descriptor() ) 
                       
                        # link from start to run
                        self.G.add_edge( n2.id, n1.id )
                        n2.add_edge( n1, {} )

                        # link from init to start
                        for init in self.vm.get_method("<init>") :
                            if init.get_class_name() == c.get_name() :
                                n3 = self._get_node( init.get_class_name(), "<init>", init.get_descriptor() )
                                #n3 = self._get_node( i.get_class_name(), "<init>", i.get_descriptor() )
                                self.G.add_edge( n3.id, n2.id )
                                n3.add_edge( n2, {} )

            #elif c.get_superclassname() == "Landroid/os/AsyncTask;" :
            #    for i in self.vm.get_method("doInBackground") :
            #        if i.get_class_name() == c.get_name() :
            #            n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
            #            n2 = self._get_exist_node( i.get_class_name(), "execute", i.get_descriptor() )
            #            print n1, n2, i.get_descriptor()
                        #for j in self.vm.get_method("doInBackground") :
                        #    n2 = self._get_exist_node( i.get_class_name(), j.get_name(), j.get_descriptor() )
                        #    print n1, n2
                        # n2 = self._get_node( i.get_class_name(), "
            #    raise("ooo")

        #for j in self.vmx.tainted_packages.get_internal_new_packages() :
        #    print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
        #                                            j.get_bb().start + j.get_idx(), \
        #                                            j.get_class_name(), j.get_name(), j.get_descriptor())


        list_permissions = self.vmx.get_permissions( [] ) 
        for x in list_permissions :
            for j in list_permissions[ x ] :
                #print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
                #                                    j.get_bb().start + j.get_idx(), \
                #                                    j.get_class_name(), j.get_name(), j.get_descriptor())
                n1 = self._get_exist_node( j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor() )

                if n1 == None :
                    continue

                n1.set_attributes( { "permissions" : 1 } )
                n1.set_attributes( { "permissions_level" : DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ x ][0] } )
                n1.set_attributes( { "permissions_details" : x } )

                try :
                    for tmp_perm in PERMISSIONS_RISK[ x ] :
                        if tmp_perm in DEFAULT_RISKS :
                            n2 = self._get_new_node( j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor() + " " + DEFAULT_RISKS[ tmp_perm ][0],
                                                     DEFAULT_RISKS[ tmp_perm ][0] )
                            n2.set_attributes( { "color" : DEFAULT_RISKS[ tmp_perm ][1] } )
                            self.G.add_edge( n2.id, n1.id )

                            n1.add_risk( DEFAULT_RISKS[ tmp_perm ][0] )
                            n1.add_api( x, j.get_class_name() + "-" + j.get_name() + "-" + j.get_descriptor() )
                except KeyError :
                    pass

        # Tag DexClassLoader
        for m, _ in self.vmx.get_tainted_packages().get_packages() :
            if m.get_info() == "Ldalvik/system/DexClassLoader;" :
                for path in m.get_paths() :
                    if path.get_access_flag() == TAINTED_PACKAGE_CREATE :
                        n1 = self._get_exist_node( path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor() )    
                        n2 = self._get_new_node( path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor() + " " + "DEXCLASSLOADER",
                                                 "DEXCLASSLOADER" )

                        n1.set_attributes( { "dynamic_code" : "true" } )
                        n2.set_attributes( { "color" : DEXCLASSLOADER_COLOR } )
                        self.G.add_edge( n2.id, n1.id )
                        
                        n1.add_risk( "DEXCLASSLOADER" )

    def _get_exist_node(self, class_name, method_name, descriptor) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        try :
            return self.nodes[ key ]
        except KeyError :
            return None

    def _get_node(self, class_name, method_name, descriptor) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes :
            self.nodes[ key ] = NodeF( len(self.nodes), class_name, method_name, descriptor )
            self.nodes_id[ self.nodes[ key ].id ] = self.nodes[ key ]

        return self.nodes[ key ]

    def _get_new_node_from(self, n, label) :
        return self._get_new_node( n.class_name, n.method_name, n.descriptor + label, label )

    def _get_new_node(self, class_name, method_name, descriptor, label) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes :
            self.nodes[ key ] = NodeF( len(self.nodes), class_name, method_name, descriptor, label, False )
            self.nodes_id[ self.nodes[ key ].id ] = self.nodes[ key ]

        return self.nodes[ key ]

    def set_new_attributes(self, cm) :
        for i in self.G.nodes() :
            n1 = self.nodes_id[ i ]
            m1 = self.vm.get_method_descriptor( n1.class_name, n1.method_name, n1.descriptor )

            H = cm( self.vmx, m1 )

            n1.set_attributes( H )

    def export_to_gexf(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        buff += "<gexf xmlns=\"http://www.gephi.org/gexf\" xmlns:viz=\"http://www.gephi.org/gexf/viz\">\n"
        buff += "<graph type=\"static\">\n"

        buff += "<attributes class=\"node\" type=\"static\">\n" 
        buff += "<attribute default=\"normal\" id=\"%d\" title=\"type\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "type"]
        buff += "<attribute id=\"%d\" title=\"class_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "class_name"]
        buff += "<attribute id=\"%d\" title=\"method_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "method_name"]
        buff += "<attribute id=\"%d\" title=\"descriptor\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "descriptor"]


        buff += "<attribute default=\"0\" id=\"%d\" title=\"permissions\" type=\"integer\"/>\n" % ID_ATTRIBUTES[ "permissions"]
        buff += "<attribute default=\"normal\" id=\"%d\" title=\"permissions_level\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "permissions_level"]
        
        buff += "<attribute default=\"false\" id=\"%d\" title=\"dynamic_code\" type=\"boolean\"/>\n" % ID_ATTRIBUTES[ "dynamic_code"]
        buff += "</attributes>\n"   

        buff += "<nodes>\n"
        for node in self.G.nodes() :
            buff += "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label))
            buff += self.nodes_id[ node ].get_attributes_gexf()
            buff += "</node>\n"
        buff += "</nodes>\n"


        buff += "<edges>\n"
        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1
        buff += "</edges>\n"


        buff += "</graph>\n"
        buff += "</gexf>\n"

        return buff

    def export_to_gml(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
        buff += "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:y=\"http://www.yworks.com/xml/graphml\" xmlns:yed=\"http://www.yworks.com/xml/yed/3\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://www.yworks.com/xml/schema/graphml/1.1/ygraphml.xsd\">\n"

        buff += "<key attr.name=\"description\" attr.type=\"string\" for=\"node\" id=\"d5\"/>\n"
        buff += "<key for=\"node\" id=\"d6\" yfiles.type=\"nodegraphics\"/>\n"

        buff += "<graph edgedefault=\"directed\" id=\"G\">\n"

        for node in self.G.nodes() :
            buff += "<node id=\"%d\">\n" % (node)
            #fd.write( "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label)) )
            buff += self.nodes_id[ node ].get_attributes_gml()
            buff += "</node>\n"

        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1

        buff += "</graph>\n"
        buff += "</graphml>\n"
        
        return buff

    def get_paths_method(self, method) :
        return self.get_paths( method.get_class_name(), method.get_name(), method.get_descriptor() )

    def get_paths(self, class_name, method_name, descriptor) :
        import connectivity_approx as ca
        paths = []
        key = "%s %s %s" % (class_name, method_name, descriptor)
       
        if key not in self.nodes :
            return paths

        for origin in self.G.nodes() : #self.entry_nodes :
            if ca.vertex_connectivity_approx(self.G, origin, self.nodes[ key ].id) > 0 :
                for path in ca.node_independent_paths(self.G, origin, self.nodes[ key ].id) :
                    if self.nodes_id[ path[0] ].real == True :
                        paths.append( path )
        return paths

    def print_paths_method(self, method) :
        self.print_paths( method.get_class_name(), method.get_name(), method.get_descriptor() )

    def print_paths(self, class_name, method_name, descriptor) :
        paths = self.get_paths( class_name, method_name, descriptor )
        for path in paths :
            print path, ":"
            print "\t",
            for p in path[:-1] :
                print self.nodes_id[ p ].label, "-->",
            print self.nodes_id[ path[-1] ].label

DEFAULT_NODE_TYPE = "normal"
DEFAULT_NODE_PERM = 0
DEFAULT_NODE_PERM_LEVEL = -1 

PERMISSIONS_LEVEL = {
    "dangerous" : 3,
    "signatureOrSystem" : 2,
    "signature" : 1,
    "normal" : 0,
}

COLOR_PERMISSIONS_LEVEL = {
    "dangerous"                 : (255, 0, 0),
    "signatureOrSystem"         : (255, 63, 63),
    "signature"                 : (255, 132, 132),
    "normal"                    : (255, 181, 181),
}

class NodeF :
    def __init__(self, id, class_name, method_name, descriptor, label=None, real=True) :
        self.class_name = class_name
        self.method_name = method_name 
        self.descriptor = descriptor

        self.id = id
        self.real = real
        self.risks = []
        self.api = {} 
        self.edges = {}

        if label == None : 
            self.label = "%s %s %s" % (class_name, method_name, descriptor)
        else :
            self.label = label

        self.attributes = { "type" : DEFAULT_NODE_TYPE,
                            "color" : None,
                            "permissions" : DEFAULT_NODE_PERM,
                            "permissions_level" : DEFAULT_NODE_PERM_LEVEL,
                            "permissions_details" : set(),
                            "dynamic_code" : "false",
                          }

    def add_edge(self, n, idx) :
        try :
            self.edges[ n ].append( idx )
        except KeyError :
            self.edges[ n ] = []
            self.edges[ n ].append( idx )

    def get_attributes_gexf(self) :
        buff = ""
        
        if self.attributes[ "color" ] != None : 
            buff += "<viz:color r=\"%d\" g=\"%d\" b=\"%d\"/>\n" % (self.attributes[ "color" ][0], self.attributes[ "color" ][1], self.attributes[ "color" ][2])
        
        buff += "<attvalues>\n"
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["class_name"], escape(self.class_name))
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["method_name"], escape(self.method_name))
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["descriptor"], escape(self.descriptor))
        
        
        if self.attributes[ "type" ] != DEFAULT_NODE_TYPE :
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["type"], self.attributes[ "type" ])
        if self.attributes[ "permissions" ] != DEFAULT_NODE_PERM :
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["permissions"], self.attributes[ "permissions" ])
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["permissions_level"], self.attributes[ "permissions_level_name" ])


        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["dynamic_code"], self.attributes[ "dynamic_code" ])

        buff += "</attvalues>\n"

        return buff

    def get_attributes_gml(self) :
        buff = ""
        
        buff += "<data key=\"d6\">\n"
        buff += "<y:ShapeNode>\n"
       
        height = 10 
        width = max(len(self.class_name), len(self.method_name))
        width = max(width, len(self.descriptor))

        buff += "<y:Geometry height=\"%f\" width=\"%f\"/>\n" % (16 * height, 8 * width)
        if self.attributes[ "color" ] != None : 
            buff += "<y:Fill color=\"#%02x%02x%02x\" transparent=\"false\"/>\n" % (self.attributes[ "color" ][0], self.attributes[ "color" ][1], self.attributes[ "color" ][2])

        buff += "<y:NodeLabel alignment=\"left\" autoSizePolicy=\"content\" fontFamily=\"Dialog\" fontSize=\"13\" fontStyle=\"plain\" hasBackgroundColor=\"false\" hasLineColor=\"false\" modelName=\"internal\" modelPosition=\"c\" textColor=\"#000000\" visible=\"true\">\n"

        label = self.class_name + "\n" + self.method_name + "\n" + self.descriptor
        buff += escape(label)

        buff += "</y:NodeLabel>\n"
        buff += "</y:ShapeNode>\n"
        buff += "</data>\n"

        return buff

    def get_attributes(self) :
        return self.attributes

    def get_attribute(self, name) :
        return self.attributes[ name ]

    def set_attributes(self, values) :
        for i in values :
            if i == "permissions" :
                self.attributes[ "permissions" ] += values[i]
            elif i == "permissions_level" :
                if values[i] > self.attributes[ "permissions_level" ] :
                    self.attributes[ "permissions_level" ] = PERMISSIONS_LEVEL[ values[i] ]
                    self.attributes[ "permissions_level_name" ] = values[i]
                    self.attributes[ "color" ] = COLOR_PERMISSIONS_LEVEL[ values[i] ]
            elif i == "permissions_details" :
                self.attributes[ i ].add( values[i] )
            else :
                self.attributes[ i ] = values[i]

    def add_risk(self, risk) :
        if risk not in self.risks :
            self.risks.append( risk )

    def add_api(self, perm, api) :
        if perm not in self.api :
            self.api[ perm ] = []

        if api not in self.api[ perm ] :
            self.api[ perm ].append( api )
