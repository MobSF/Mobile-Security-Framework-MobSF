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


class LoopType(object):
    def __init__(self):
        self.loop = None

    def pretest(self):
        return self.loop == 0

    def posttest(self):
        return self.loop == 1

    def endless(self):
        return self.loop == 2

    def set_pretest(self):
        self.loop = 0

    def set_posttest(self):
        self.loop = 1

    def set_endless(self):
        self.loop = 2


class Node(object):
    def __init__(self, name):
        self.name = name
        self.num = 0
        self.looptype = LoopType()
        self.interval = None
        self.startloop = False
        self.endloop = False
        self.type = -1
        self.latch = None
        self.if_follow = None
        self.loop_follow = None
        self.switch_follow = None
        self.loop_nodes = []

    def copy_from(self, node):
        self.num = node.num
        self.looptype = node.looptype
        self.interval = node.interval
        self.startloop = node.startloop
        self.endloop = node.endloop
        self.type = node.type
        self.latch = node.latch
        self.if_follow = node.if_follow
        self.loop_follow = node.loop_follow
        self.switch_follow = node.switch_follow
        self.loop_nodes = node.loop_nodes

    def update_attribute_with(self, n_map):
        self.latch = n_map.get(self.latch, self.latch)
        self.if_follow = n_map.get(self.if_follow, self.if_follow)
        self.loop_follow = n_map.get(self.loop_follow, self.loop_follow)
        self.switch_follow = n_map.get(self.switch_follow, self.switch_follow)
        self.loop_nodes = list(set(n_map.get(n, n) for n in self.loop_nodes))

    def is_cond(self):
        return self.type == 0

    def set_cond(self):
        self.type = 0

    def is_switch(self):
        return self.type == 1

    def set_switch(self):
        self.type = 1

    def is_stmt(self):
        return self.type == 2

    def set_stmt(self):
        self.type = 2

    def is_return(self):
        return self.type == 3

    def set_return(self):
        self.type = 3

    def is_throw(self):
        return self.type == 4

    def set_throw(self):
        self.type = 4

    def set_loop_pretest(self):
        self.looptype.set_pretest()

    def set_loop_posttest(self):
        self.looptype.set_posttest()

    def set_loop_endless(self):
        self.looptype.set_endless()

    def get_head(self):
        return self

    def get_end(self):
        return self

    def set_loop_nodes(self, nodes):
        self.loop_nodes = nodes

    def set_start_loop(self, b=True):
        self.startloop = b

    def set_end_loop(self, b=True):
        self.endloop = b

    def set_if_follow(self, node):
        self.if_follow = node

    def get_if_follow(self):
        return self.if_follow

    def set_loop_follow(self, node):
        self.loop_follow = node

    def get_loop_follow(self):
        return self.loop_follow

    def set_switch_follow(self, node):
        self.switch_follow = node

    def get_switch_follow(self):
        return self.switch_follow

    def set_latch_node(self, node):
        self.latch = node

    def is_start_loop(self):
        return self.startloop

    def is_end_loop(self):
        return self.endloop

    def __repr__(self):
        return str(self)


class Interval(Node):
    def __init__(self, head):
        super(Interval, self).__init__(head.name)
        self.name = 'Interval-%s' % head.name
        self.content = set([head])
        self.end = None
        self.head = head
        head.interval = self

    def __contains__(self, item):
        # If the interval contains nodes, check if the item is one of them
        if item in self.content:
            return True
        # If the interval contains intervals, we need to check them
        return any(item in node for node in self.content
                                if isinstance(node, Interval))

    def add_node(self, node):
        if node in self.content:
            return False
        self.content.add(node)
        node.interval = self
        return True

    def compute_end(self, graph):
        for node in self.content:
            for suc in graph.sucs(node):
                if suc not in self.content:
                    self.end = node

    def get_end(self):
        return self.end.get_end()

    def set_next(self, nxt):
        self.head.set_next(nxt.get_head())

    def get_next(self):
        return self.head.get_next()

    def set_loop_type(self, _type):
        self.looptype = _type
        self.get_head().set_loop_type(_type)

    def set_startloop(self):
        self.head.set_startloop()

    def get_head(self):
        return self.head.get_head()

    def __iter__(self):
        for item in self.content:
            yield item

    def __len__(self):
        return len(self.content)

    def __repr__(self):
        return '%s(%s)' % (self.name, self.content)
