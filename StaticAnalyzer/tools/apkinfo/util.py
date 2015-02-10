#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

# Androguard imports

from StaticAnalyzer.tools.apkinfo.apk import *

# Androwarn modules import
from StaticAnalyzer.tools.apkinfo.api_constants import *

# Global imports
import re, logging
from HTMLParser import HTMLParser

# Logguer
log = logging.getLogger('log')

def convert_dex_to_canonical(dex_name) :
	"""
		@param dex_name : a dex name, for instance "Lcom/name/test"
	
		@rtype : a dotted string, for instance "com.name.test"
	"""
	final_name = ''
	if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', dex_name) :
		global_part = dex_name[1:-1].split('/')
		final_part = global_part[:-1]
		last_part = global_part[-1].split('$')[0]
		final_part.append(str(last_part))
		final_name = '.'.join(str(i) for i in final_part)
	else :
		return "[!] Conversion to canonical dotted name failed : \"" + dex_name + "\" is not a valid library dex name"
	return final_name

def convert_canonical_to_dex(canonical_name) :
	return 'L' + canonical_name.replace('.', '/')

def detector_tab_is_not_empty(list) :
	"""
		@param list : a list of result
	
		@rtype : False if all the items in the list are empty, True otherwise
	"""
	for item in list :
		if not(not(item)) :
			return True
	return False

# Log extra information
def log_result_path_information(res, res_prefix, res_type) :
	"""
		@param res : a result from the detector's result list
		@param res_prefix : result's category name
		@param res_type : result's type
	
		@rtype : void - it only logs extra information about the analysis result
	"""
	res_info = res.get_info()
	if len(res_info) > 0:
		paths = res.get_paths()
		
		for path in res.get_paths() :
			access, idx = path[0]
			m_idx = path[1]
			log.info("'%s' %s found '%s'" % (res_prefix, res_type, res_info ) )
			log.debug("\t=> access_flag %s, index %s, method_index %s" % (access, idx, m_idx))

# HTML Sanitizer
class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_HTML_tags(html):
	"""
		@param html : a string to be cleaned up
	
		@rtype : a HTML-tag sanitized string
	"""
	# Keep the indentation
	html = html.replace('<br>', '\n')
	
	# Remove HTML tags
	s = MLStripper()
	s.feed(html)
	
	return s.get_data()

# Data tab cleaner
def clean_list(list_to_clean,purge_list) :
	"""
		@param list_to_clean : a list to be cleaned up
		@param purge_list : the list of elements to remove in the list
	
		@rtype : a cleaned list
	"""
	if list_to_clean and purge_list :
		for i in reversed(purge_list) :
			del list_to_clean[i]

# Dump
def flush_simple_string(string, file) :
	"""
		@param string : a unique string
		@param file : output file descriptor
	"""
	file.write("%s\n" % string)

def dump_analysis_results(data, file_descriptor) :
	"""
		@param data : analysis results list
		@param file_descriptor : dump output, file or sys.stdout
	
		@rtype : void - it only prints out the list
	"""
	# Watch out for encoding error while priting
	flush_simple_string("===== Androwarn Report =====", file_descriptor)
	if data :
		for item in data :
			for category, element_tuple in item.iteritems() :
				if isinstance(category,str) :
					flush_simple_string("[+] %s" % category.encode('ascii','ignore').replace('_',' ').title(), file_descriptor)
				for name,content in element_tuple :
					if content and isinstance(name,str) :
						flush_simple_string("\t[.] %s" % (name.encode('ascii','ignore').replace('_',' ').title().ljust(40)), file_descriptor)
						for element in content :
							if isinstance(element,str) :
								flush_simple_string("\t\t- %s" % element.encode('ascii','ignore'), file_descriptor)
						flush_simple_string("", file_descriptor)
				flush_simple_string("", file_descriptor)

# Classes harvesting
def search_class(x, package_name) :
	"""
		@param x : a VMAnalysis instance
		@param package_name : a regexp for the name of the package
	
		@rtype : a list of classes' paths
	"""
	return x.tainted_packages.search_packages( package_name )

def search_field(x, field_name) :
	"""
		@param x : a VMAnalysis instance
		@param field_name : a regexp for the field name
	
		@rtype : a list of classes' paths
	"""
	for f, _ in x.tainted_variables.get_fields() :
		field_info = f.get_info()
		if field_name in field_info :
			return f
	return []

def search_string(x, string_name) :
	"""
		@param x : a VMAnalysis instance
		@param string_name : a regexp for the string name
	
		@rtype : a list of classes' paths
	"""
	for s, _ in x.tainted_variables.get_strings() :
		string_info = s.get_info()
		if string_name in string_info :
			return s
	return []

def search_class_in_the_list(canonical_class_list,canonical_class_name):
	"""
		@param canonical_class_list : a canonical list of classes
		@param canonical_class_name : a regexp for the name of the class
	
		@rtype : a list of class names
	"""
	l = []
	ex = re.compile( canonical_class_name )
	l = filter(ex.search, canonical_class_list)
	
	return l

def search_package_in_the_list(canonical_package_list,canonical_package_name):
	"""
		@param canonical_package_list : a canonical list of package
		@param canonical_package_name : a regexp for the name of the package

	
		@rtype : a list of packages names
	"""
	l = []
	ex = re.compile( canonical_package_name )   
	l = filter(ex.search, canonical_package_list)
	
	return l

# XML parsing
def get_parent_child_grandchild(tree):
	"""
		@param tree : xml root Element
	
		@rtype : parent, child and grandchild Element
	"""
	for parent in tree.getiterator() :
		for child in parent :
			for grandchild in child :
				yield parent, child, grandchild

# Bulk structural analysis
def bulk_structural_analysis(class_name, list, x) :
	"""
		@param list : a list of tuple (class function name, class function description)
	
		@rtype : a list of strings related to the findings
	"""
	formatted_str = []
	
	for method_name, description in list :
		structural_analysis_results = x.tainted_packages.search_methods(class_name,method_name, ".")
		if structural_analysis_results :
			formatted_str.append(description)
	
	return formatted_str

# OR Bitwise option recovery
def recover_bitwise_flag_settings(flag, constants_dict) :
	"""
		@param flag : an integer value to be matched with bitwise OR options set
		@param constants_dict : a dictionary containing each options' integer value
	
		@rtype : a string summing up settings
	"""
	recover = ''
	options = []
	
	for option_value in constants_dict :
		if (int(flag) & option_value) == option_value :
			options.append(constants_dict[option_value])
			
	recover = ', '.join(i for i in options)
	
	return recover

# Check if extracted values are ALL register numbers, following the pattern 'v[0-9]+', as they obviously are register number and thus useless
def isnt_all_regs_values(list) :
	"""
		@param list : a list of strings, extracted from the data flow analysis
	
		@rtype : a boolean, True if there's at least 1 non-register number value, Else False
	"""
	result = False
	p_reg = re.compile ('^v[0-9]+$')
	
	for i in list :
		if not(p_reg.match(i)) :
			result = True
	
	return result
