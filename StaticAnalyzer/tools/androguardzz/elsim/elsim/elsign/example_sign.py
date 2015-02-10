#!/usr/bin/env python

import sys

PATH_INSTALL = "./libelsign"
sys.path.append(PATH_INSTALL)

from libelsign import libelsign
#from libelsign import libelsign2 as libelsign

SIGNS = [ 
            [ "Sign1", "a",
                [ [ 4.4915299415588379, 4.9674844741821289,
                    4.9468302726745605, 0.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ] ],
            [ "Sign2", "a && b",
                [ [ 2.0, 3.0, 4.0, 5.0 ], "OOOPS !!!!!!!!" ], [ [ 2.0, 3.0, 4.0, 8.0], "OOOOOOOOPPPPPS !!!" ] ],
]
HSIGNS = {}

ELEMS = [
#            [ [ 4.4915299415588379, 4.9674844741821289, 4.9468302726745605, 0.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ],
            [ [ 4.4915299415588379, 4.9674844741821289, 4.9468302726745605, 1.0 ], "FALSE POSITIVE" ],
            [ [ 2.0, 3.0, 4.0, 5.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ],
            [ [ 2.0, 3.0, 4.0, 5.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ],
            [ [ 2.0, 3.0, 4.0, 5.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ],
            [ [ 2.0, 3.0, 4.0, 5.0 ], "HELLO WORLDDDDDDDDDDDDDDDDDDDDDDD" ],
]
HELEMS = {}

es = libelsign.Elsign()

es.set_debug_log(1)

es.set_distance( 'e' )
es.set_method( 'm' )
es.set_weight( [ 2.0, 1.2, 0.5, 0.1, 0.6 ] )

# NCD
es.set_sim_method( 0 )
es.set_threshold_low( 0.3 )
es.set_threshold_high( 0.4 )
# SNAPPY
es.set_ncd_compression_algorithm( 5 )


for i in range(0, len(SIGNS)) :
    id = es.add_signature( SIGNS[i][0], SIGNS[i][1], SIGNS[i][2:] )
    print SIGNS[i], id
    HSIGNS[id] = i

for i in range(0, len(ELEMS)) :
    id = es.add_element( ELEMS[i][1], ELEMS[i][0] )
    print ELEMS[i], id
    HELEMS[id] = i

print es.check()

dt = es.get_debug()
debug_nb_sign = dt[0]
debug_nb_clusters = dt[1]
debug_nb_cmp_clusters = dt[2]
debug_nb_elements = dt[3]
debug_nb_cmp_elements = dt[4]
debug_nb_cmp_max = debug_nb_sign * debug_nb_elements
print "[SIGN:%d CLUSTERS:%d CMP_CLUSTERS:%d ELEMENTS:%d CMP_ELEMENTS:%d" % (debug_nb_sign, debug_nb_clusters, debug_nb_cmp_clusters, debug_nb_elements, debug_nb_cmp_elements),
print "-> %d %f%%]" % (debug_nb_cmp_max, ((debug_nb_cmp_elements/float(debug_nb_cmp_max)) * 100) )
