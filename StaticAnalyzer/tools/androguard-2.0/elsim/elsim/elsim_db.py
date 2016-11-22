#!/usr/bin/env python

# This file is part of Elsim.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Elsim is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Elsim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Elsim.  If not, see <http://www.gnu.org/licenses/>.

import re

from similarity.similarity import DBFormat, simhash
from androguard.core.analysis import analysis

DEFAULT_SIGNATURE = analysis.SIGNATURE_SEQUENCE_BB

def eval_res_per_class(ret):
    z = {}

    for i in ret:
        for j in ret[i]:
            for k in ret[i][j]:
                val = ret[i][j][k]
            #    print val, k
                if len(val[0]) == 1 and val[1] > 1:
                    continue

                if len(val[0]) == 0:
                    continue

                if j not in z:
                    z[j] = {}

                val_percentage = (len(val[0]) / float(val[1]) ) * 100
                if (val_percentage != 0):
                    z[j][k] = val_percentage
    return z

############################################################

class ElsimDB(object):
  def __init__(self, database_path):
      self.db = DBFormat( database_path )

  def eval_res(self, ret, info, threshold=10.0):
      sorted_elems = {}

      for i in ret:
          sorted_elems[i] = []
          for j in ret[i]:
              t_size = 0

              elems = set()
              for k in ret[i][j]:
                  val = ret[i][j][k]

                  if len(val[0]) == 1 and val[1] > 1:
                    continue

                  t_size += val[-1]
                  elems.add( k )


              percentage_size = (t_size / float(info[i][j]["SIZE"])) * 100

              if percentage_size > threshold:
                sorted_elems[i].append( (j, percentage_size, elems) )

          if len(sorted_elems[i]) == 0:
            del sorted_elems[i]

      return sorted_elems

  def percentages(self, vm, vmx, threshold=10):
      elems_hash = set()
      for _class in vm.get_classes():
          for method in _class.get_methods():
              code = method.get_code()
              if code == None:
                  continue

              buff_list = vmx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

              for i in buff_list:
                  elem_hash = long(simhash( i ))
                  elems_hash.add( elem_hash )

      ret, info = self.db.elems_are_presents( elems_hash )
      sorted_ret = self.eval_res(ret, info, threshold)


      info = {}

      for i in sorted_ret:
          v = sorted(sorted_ret[i], key=lambda x: x[1])
          v.reverse()

          info[i] = []

          for j in v:
             info[i].append( [j[0], j[1]] )

      info_name = self.db.classes_are_presents( vm.get_classes_names() )

      for i in info_name:
        if i not in info:
          info[i] = None

      return info

  def percentages_code(self, exclude_list):
      libs = re.compile('|'.join( "(" + i + ")" for i in exclude_list))

      classes_size = 0
      classes_db_size = 0
      classes_edb_size = 0
      classes_udb_size = 0

      for _class in self.vm.get_classes():
          class_size = 0
          elems_hash = set()
          for method in _class.get_methods():
              code = method.get_code()
              if code == None:
                  continue

              buff_list = self.vmx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

              for i in buff_list:
                  elem_hash = long(simhash( i ))
                  elems_hash.add( elem_hash )

              class_size += method.get_length()

          classes_size += class_size

          if class_size == 0:
              continue

          ret = self.db.elems_are_presents( elems_hash )
          sort_ret = eval_res_per_class( ret )
          if sort_ret == {}:
              if libs.search(_class.get_name()) != None:
                  classes_edb_size += class_size
              else:
                classes_udb_size += class_size
          else:
            classes_db_size += class_size

      return (classes_db_size/float(classes_size)) * 100, (classes_edb_size/float(classes_size)) * 100, (classes_udb_size/float(classes_size)) * 100

  def percentages_to_graph(self):
      info = { "info" : [], "nodes" : [], "links" : []}
      N = {}
      L = {}

      for _class in self.vm.get_classes():
          elems_hash = set()
      #    print _class.get_name()
          for method in _class.get_methods():
              code = method.get_code()
              if code == None:
                  continue

              buff_list = self.vmx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

              for i in buff_list:
                  elem_hash = long(simhash( i ))
                  elems_hash.add( elem_hash )

          ret = self.db.elems_are_presents( elems_hash )
          sort_ret = eval_res_per_class( ret )

          if sort_ret != {}:
              if _class.get_name() not in N:
                  info["nodes"].append( { "name" : _class.get_name().split("/")[-1], "group" : 0 } )
                  N[_class.get_name()] = len(N)

              for j in sort_ret:
                  if j not in N:
                      N[j] = len(N)
                      info["nodes"].append( { "name" : j, "group" : 1 } )

                  key = _class.get_name() + j
                  if key not in L:
                      L[ key ] = { "source" : N[_class.get_name()], "target" : N[j], "value" : 0 }
                      info["links"].append( L[ key ] )

                  for k in sort_ret[j]:
                      if sort_ret[j][k] > L[ key ]["value"]:
                          L[ key ]["value"] = sort_ret[j][k]

      return info


class ElsimDBIn(object):
  def __init__(self, output):
    self.db = DBFormat( output )


  def add_name(self, name, value):
    self.db.add_name( name, value )

  def add(self, d, dx, name, sname, regexp_pattern, regexp_exclude_pattern):
   for _class in d.get_classes():
    if regexp_pattern != None:
        if re.match(regexp_pattern, _class.get_name()) == None:
            continue
    if regexp_exclude_pattern != None:
        if re.match(regexp_exclude_pattern, _class.get_name()) != None:
            continue

    print "\t", _class.get_name()
    for method in _class.get_methods():
        code = method.get_code()
        if code == None:
            continue

        if method.get_length() < 50 or method.get_name() == "<clinit>" or method.get_name() == "<init>":
            continue

        buff_list = dx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()
        if len(set(buff_list)) == 1:
            continue

        for e in buff_list:
            self.db.add_element( name, sname, _class.get_name(), method.get_length(), long(simhash(e)) )

  def save(self):
    self.db.save()