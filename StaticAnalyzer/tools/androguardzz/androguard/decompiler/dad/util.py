# This file is part of Androguard.
#
# Copyright (c) 2012 Geoffroy Gueguen <geoffroy.gueguen@gmail.com>
# All Rights Reserved.
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

import logging

logger = logging.getLogger('dad.util')

TYPE_DESCRIPTOR = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
    'STR': 'String',
    'StringBuilder': 'String',
}

ACCESS_FLAGS_CLASSES = {
    0x1:    'public',
    0x2:    'private',
    0x4:    'protected',
    0x8:    'static',
    0x10:   'final',
    0x200:  'interface',
    0x400:  'abstract',
    0x1000: 'synthetic',
    0x2000: 'annotation',
    0x4000: 'enum',
}

ACCESS_FLAGS_FIELDS = {
    0x1:    'public',
    0x2:    'private',
    0x4:    'protected',
    0x8:    'static',
    0x10:   'final',
    0x40:   'volatile',
    0x80:   'transient',
    0x1000: 'synthetic',
    0x4000: 'enum',
}

ACCESS_FLAGS_METHODS = {
    0x1:     'public',
    0x2:     'private',
    0x4:     'protected',
    0x8:     'static',
    0x10:    'final',
    0x20:    'synchronized',
    0x40:    'bridge',
    0x80:    'varargs',
    0x100:   'native',
    0x400:   'abstract',
    0x800:   'strict',
    0x1000:  'synthetic',
    # ACC_CONSTRUCTOR
    0x10000: '',
    0x20000: 'synchronized',
}

TYPE_LEN = {
    'J': 2,
    'D': 2,
}


def build_path(graph, node1, node2, path=None):
    '''
    Build the path from node1 to node2.
    The path is composed of all the nodes between node1 and node2,
    node1 excluded. Although if there is a loop starting from node1, it will be
    included in the path.
    '''
    if path is None:
        path = []
    if node1 is node2:
        return path
    path.append(node2)
    for pred in graph.preds(node2):
        if pred in path:
            continue
        build_path(graph, node1, pred, path)
    return path


def common_dom(idom, cur, pred):
    if not (cur and pred):
        return cur or pred
    while cur is not pred:
        while cur.num < pred.num:
            pred = idom[pred]
        while cur.num > pred.num:
            cur = idom[cur]
    return cur


def merge_inner(clsdict):
    '''
    Merge the inner class(es) of a class :
    e.g class A { ... } class A$foo{ ... } class A$bar{ ... }
       ==> class A { class foo{...} class bar{...} ... }
    '''
    samelist = False
    done = {}
    while not samelist:
        samelist = True
        classlist = clsdict.keys()
        for classname in classlist:
            parts_name = classname.rsplit('$', 1)
            if len(parts_name) > 1:
                mainclass, innerclass = parts_name
                innerclass = innerclass[:-1]  # remove ';' of the name
                mainclass += ';'
                if mainclass in clsdict:
                    clsdict[mainclass].add_subclass(innerclass,
                                                    clsdict[classname])
                    clsdict[classname].name = innerclass
                    done[classname] = clsdict[classname]
                    del clsdict[classname]
                    samelist = False
                elif mainclass in done:
                    cls = done[mainclass]
                    cls.add_subclass(innerclass, clsdict[classname])
                    clsdict[classname].name = innerclass
                    done[classname] = done[mainclass]
                    del clsdict[classname]
                    samelist = False


def get_type_size(param):
    '''
    Return the number of register needed by the type @param
    '''
    return TYPE_LEN.get(param, 1)


def get_type(atype, size=None):
    '''
    Retrieve the java type of a descriptor (e.g : I)
    '''
    res = TYPE_DESCRIPTOR.get(atype)
    if res is None:
        if atype[0] == 'L':
            if atype.startswith('Ljava/lang'):
                res = atype[1:-1].lstrip('java/lang/').replace('/', '.')
            else:
                res = atype[1:-1].replace('/', '.')
        elif atype[0] == '[':
            if size is None:
                res = '%s[]' % get_type(atype[1:])
            else:
                res = '%s[%s]' % (get_type(atype[1:]), size)
        else:
            res = atype
            logger.debug('Unknown descriptor: "%s".', atype)
    return res


def get_params_type(descriptor):
    '''
    Return the parameters type of a descriptor (e.g (IC)V)
    '''
    params = descriptor.split(')')[0][1:].split()
    if params:
        return [param for param in params]
    return []


def create_png(cls_name, meth_name, graph, dir_name='graphs2'):
    m_name = ''.join(x for x in meth_name if x.isalnum())
    name = ''.join(cls_name.split('/')[-1][:-1], '#', m_name)
    graph.draw(name, dir_name)
