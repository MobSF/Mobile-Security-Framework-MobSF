import unittest
import os

from altgraph import Dot
from altgraph import Graph
from altgraph import GraphError


class TestDot (unittest.TestCase):

    def test_constructor(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g)

        self.assertEqual(dot.name, 'G')
        self.assertEqual(dot.attr, {})
        self.assertEqual(dot.temp_dot, 'tmp_dot.dot')
        self.assertEqual(dot.temp_neo, 'tmp_neo.dot')
        self.assertEqual(dot.dot, 'dot')
        self.assertEqual(dot.dotty, 'dotty')
        self.assertEqual(dot.neato, 'neato')
        self.assertEqual(dot.type, 'digraph')

        self.assertEqual(dot.nodes, dict([(x, {}) for x in g]))

        edges = {}
        for head in g:
            edges[head] = {}
            for tail in g.out_nbrs(head):
                edges[head][tail] = {}

        self.assertEqual(dot.edges[1], edges[1])
        self.assertEqual(dot.edges, edges)


        dot = Dot.Dot(g, nodes=[1,2],
                edgefn=lambda node: list(sorted(g.out_nbrs(node)))[:-1],
                nodevisitor=lambda node: {'label': node},
                edgevisitor=lambda head, tail: {'label': (head, tail) },
                name="testgraph",
                dot='/usr/local/bin/dot',
                dotty='/usr/local/bin/dotty',
                neato='/usr/local/bin/neato',
                graphtype="graph")

        self.assertEqual(dot.name, 'testgraph')
        self.assertEqual(dot.attr, {})
        self.assertEqual(dot.temp_dot, 'tmp_dot.dot')
        self.assertEqual(dot.temp_neo, 'tmp_neo.dot')
        self.assertEqual(dot.dot, '/usr/local/bin/dot')
        self.assertEqual(dot.dotty, '/usr/local/bin/dotty')
        self.assertEqual(dot.neato, '/usr/local/bin/neato')
        self.assertEqual(dot.type, 'graph')

        self.assertEqual(dot.nodes, dict([(x, {'label': x}) for x in [1,2]]))

        edges = {}
        for head in [1,2]:
            edges[head] = {}
            for tail in list(sorted(g.out_nbrs(head)))[:-1]:
                if tail not in [1,2]: continue
                edges[head][tail] = {'label': (head, tail) }

        self.assertEqual(dot.edges[1], edges[1])
        self.assertEqual(dot.edges, edges)

        self.assertRaises(GraphError, Dot.Dot, g, nodes=[1,2, 9])

    def test_style(self):
        g = Graph.Graph([])

        dot = Dot.Dot(g)

        self.assertEqual(dot.attr, {})

        dot.style(key='value')
        self.assertEqual(dot.attr, {'key': 'value'})

        dot.style(key2='value2')
        self.assertEqual(dot.attr, {'key2': 'value2'})

    def test_node_style(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g)

        self.assertEqual(dot.nodes[1], {})

        dot.node_style(1, key='value')
        self.assertEqual(dot.nodes[1], {'key': 'value'})

        dot.node_style(1, key2='value2')
        self.assertEqual(dot.nodes[1], {'key2': 'value2'})
        self.assertEqual(dot.nodes[2], {})

        dot.all_node_style(key3='value3')
        for n in g:
            self.assertEqual(dot.nodes[n], {'key3': 'value3'})

        self.assertTrue(9 not in dot.nodes)
        dot.node_style(9, key='value')
        self.assertEqual(dot.nodes[9], {'key': 'value'})

    def test_edge_style(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g)

        self.assertEqual(dot.edges[1][2], {})
        dot.edge_style(1,2, foo='bar')
        self.assertEqual(dot.edges[1][2], {'foo': 'bar'})

        dot.edge_style(1,2, foo2='2bar')
        self.assertEqual(dot.edges[1][2], {'foo2': '2bar'})

        self.assertEqual(dot.edges[1][3], {})

        self.assertFalse(6 in dot.edges[1])
        dot.edge_style(1,6, foo2='2bar')
        self.assertEqual(dot.edges[1][6], {'foo2': '2bar'})

        self.assertRaises(GraphError, dot.edge_style, 1, 9, a=1)
        self.assertRaises(GraphError, dot.edge_style, 9, 1, a=1)


    def test_iter(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g)
        dot.style(graph="foobar")
        dot.node_style(1, key='value')
        dot.node_style(2, key='another', key2='world')
        dot.edge_style(1,4, key1='value1', key2='value2')
        dot.edge_style(2,4, key1='valueA')

        self.assertEqual(list(iter(dot)), list(dot.iterdot()))

        for item in dot.iterdot():
            self.assertTrue(isinstance(item, str))

        first = list(dot.iterdot())[0]
        self.assertEqual(first, "digraph %s {\n"%(dot.name,))

        dot.type = 'graph'
        first = list(dot.iterdot())[0]
        self.assertEqual(first, "graph %s {\n"%(dot.name,))

        dot.type = 'foo'
        self.assertRaises(GraphError, list, dot.iterdot())
        dot.type = 'digraph'

        self.assertEqual(list(dot), [
            'digraph G {\n',
              'graph="foobar";',
              '\n',

            '\t"1" [',
              'key="value",',
            '];\n',

            '\t"2" [',
              'key="another",',
              'key2="world",',
            '];\n',

            '\t"3" [',
            '];\n',

            '\t"4" [',
            '];\n',

            '\t"6" [',
            '];\n',

            '\t"7" [',
            '];\n',

            '\t"1" -> "2" [',
            '];\n',

            '\t"1" -> "3" [',
            '];\n',

            '\t"1" -> "4" [',
              'key1="value1",',
              'key2="value2",',
            '];\n',

             '\t"2" -> "4" [',
               'key1="valueA",',
             '];\n',

             '\t"2" -> "6" [',
             '];\n',

             '\t"2" -> "7" [',
             '];\n',

             '\t"6" -> "1" [',
             '];\n',

             '\t"7" -> "4" [',
             '];\n',
           '}\n'])


    def test_save(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g)
        dot.style(graph="foobar")
        dot.node_style(1, key='value')
        dot.node_style(2, key='another', key2='world')
        dot.edge_style(1,4, key1='value1', key2='value2')
        dot.edge_style(2,4, key1='valueA')

        fn = 'test_dot.dot'
        self.assertTrue(not os.path.exists(fn))

        try:
            dot.save_dot(fn)

            fp = open(fn, 'r')
            data = fp.read()
            fp.close()
            self.assertEqual(data, ''.join(dot))

        finally:
            if os.path.exists(fn):
                os.unlink(fn)


    def test_img(self):
        g = Graph.Graph([
                (1,2),
                (1,3),
                (1,4),
                (2,4),
                (2,6),
                (2,7),
                (7,4),
                (6,1),
            ]
        )

        dot = Dot.Dot(g, dot='/usr/local/bin/!!dot', dotty='/usr/local/bin/!!dotty', neato='/usr/local/bin/!!neato')
        dot.style(size='10,10', rankdir='RL', page='5, 5' , ranksep=0.75)
        dot.node_style(1, label='BASE_NODE',shape='box', color='blue')
        dot.node_style(2, style='filled', fillcolor='red')
        dot.edge_style(1,4, style='dotted')
        dot.edge_style(2,4, arrowhead='dot', label='binds', labelangle='90')

        system_cmds = []
        def fake_system(cmd):
            system_cmds.append(cmd)
            return None

        try:
            real_system = os.system
            os.system = fake_system

            system_cmds = []
            dot.save_img('foo')
            self.assertEqual(system_cmds, ['/usr/local/bin/!!dot -Tgif tmp_dot.dot -o foo.gif'])

            system_cmds = []
            dot.save_img('foo', file_type='jpg')
            self.assertEqual(system_cmds, ['/usr/local/bin/!!dot -Tjpg tmp_dot.dot -o foo.jpg'])

            system_cmds = []
            dot.save_img('bar', file_type='jpg', mode='neato')
            self.assertEqual(system_cmds, [
                '/usr/local/bin/!!neato -o tmp_dot.dot tmp_neo.dot',
                '/usr/local/bin/!!dot -Tjpg tmp_dot.dot -o bar.jpg',
            ])

            system_cmds = []
            dot.display()
            self.assertEqual(system_cmds, [
                '/usr/local/bin/!!dotty tmp_dot.dot'
            ])

            system_cmds = []
            dot.display(mode='neato')
            self.assertEqual(system_cmds, [
                '/usr/local/bin/!!neato -o tmp_dot.dot tmp_neo.dot',
                '/usr/local/bin/!!dotty tmp_dot.dot'
            ])

        finally:
            if os.path.exists(dot.temp_dot):
                os.unlink(dot.temp_dot)
            if os.path.exists(dot.temp_neo):
                os.unlink(dot.temp_neo)
            os.system = real_system

        if os.path.exists('/usr/local/bin/dot') and os.path.exists('/usr/local/bin/neato'):
            try:
                dot.dot='/usr/local/bin/dot'
                dot.neato='/usr/local/bin/neato'
                self.assertFalse(os.path.exists('foo.gif'))
                dot.save_img('foo')
                self.assertTrue(os.path.exists('foo.gif'))
                os.unlink('foo.gif')

                self.assertFalse(os.path.exists('foo.gif'))
                dot.save_img('foo', mode='neato')
                self.assertTrue(os.path.exists('foo.gif'))
                os.unlink('foo.gif')

            finally:
                if os.path.exists(dot.temp_dot):
                    os.unlink(dot.temp_dot)
                if os.path.exists(dot.temp_neo):
                    os.unlink(dot.temp_neo)


if __name__ == "__main__": # pragma: no cover
    unittest.main()
