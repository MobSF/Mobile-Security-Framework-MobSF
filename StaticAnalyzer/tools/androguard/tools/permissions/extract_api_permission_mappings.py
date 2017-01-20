#!/usr/bin/env python

# This file is part of Androguard.
#
# This is a tool to extract permissions and permission groups from Android Open Source Project.
# The information about the permissions and permission groups is appended to a file, which is 
# later used in Androguard project.
# 
# Author: Yury Zhauniarovich
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. 

#CONSTANTS
PATH_TO_PSCOUT_FOLDER = "/home/yury/TMP/PScout/results/API_09"
API_VERSION = 9


MAPPINGS_MODULE_PATH = "../../androguard/core/api_specific_resources/api_permission_mappings/"    #where to append the results
MAPPINGS_MODULE_NAME = "api_permission_mappings"

PSCOUT_METHOD_MAPPING_FILENAME = "allmappings"
PSCOUT_CONTENTPROVIDERFIELDS_MAPPING_FILENAME = "contentproviderfieldpermission"

METHODS_MAPPING_PARAM_NAME = "AOSP_PERMISSIONS_BY_METHODS"
FIELDS_MAPPING_PARAM_NAME = "AOSP_PERMISSIONS_BY_FIELDS"


#IMPORTS
import os, re, codecs


#auxiliary
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
}

DESCRIPTOR_TYPE = {
    'void'    : 'V',
    'boolean' : 'Z',
    'byte'    : 'B',
    'short'   : 'S',
    'char'    : 'C',
    'int'     : 'I',
    'long'    : 'J',
    'float'   : 'F',
    'double'  : 'D',
}

def countBrackets(atype):
    res = re.findall('\[\s*\]', atype)
    return len(res)

def transformClassParam(atype):
    res = ""
    arrDim = countBrackets(atype)
    if arrDim > 0:
        pos = atype.find('[')
        atype = atype[0 : pos].strip()
        res = '['*arrDim
    
    if atype in DESCRIPTOR_TYPE:
        res += DESCRIPTOR_TYPE[atype]
    else:
        res += FormatClassToJava(atype)
    
    return res
     

def FormatClassToJava(input) :
    """
       Transoform a typical xml format class into java format

       :param input: the input class name
       :rtype: string
    """
    return "L" + input.replace(".", "/") + ";"
        

def parseMethod(methodString):
    ms = methodString.strip()
    
    mParamStartPos = ms.find('(')
    mParamEndPos = ms.find(')')
    paramString = ms[mParamStartPos + 1 : mParamEndPos].strip()
    params = [l.strip() for l in paramString.split(',')]
    
    retValue_mName = ms[0 : mParamStartPos].strip()
    mNameStartPos = retValue_mName.rfind(' ')
    returnValue = retValue_mName[0 : mNameStartPos].strip()
    methodName = retValue_mName[mNameStartPos + 1 : ].strip()
    
    return (methodName, params, returnValue)
#end of auxiliary






print "Starting conversion of PScout data: [%s]" % PATH_TO_PSCOUT_FOLDER

if not os.path.exists(MAPPINGS_MODULE_PATH):
    os.makedirs(MAPPINGS_MODULE_PATH)

print "Checking if we already have the file with the version %d..." % API_VERSION
api_specific_mappings_module_name = "%s_api%s.py" % (MAPPINGS_MODULE_NAME, API_VERSION)
api_specific_mappings_module_path = os.path.join(MAPPINGS_MODULE_PATH, api_specific_mappings_module_name)
if os.path.exists(api_specific_mappings_module_path):
    print "API specific file for this version already exists!"
    print "If you want create a file for newer version, please, delete file: %s" % api_specific_mappings_module_path
    exit(1)




print "Reading method mapping file..."    
pscout_method_mapping_filepath = os.path.join(PATH_TO_PSCOUT_FOLDER, PSCOUT_METHOD_MAPPING_FILENAME)
methods_mapping_file_lines = []
with open(pscout_method_mapping_filepath, 'r') as pscout_file:
    methods_mapping_file_lines = pscout_file.readlines()


print "Starting to parse file: [%s]" % pscout_method_mapping_filepath
perm_name = None
methods_mapping = {}
for line in methods_mapping_file_lines:
    line = line.strip()
    if line.startswith("Permission:"):
        perm_name = line.split("Permission:")[1].strip()
        print "PROCESSING PERMISSIONS: %s" % perm_name
    elif line.startswith("<"):
        class_method = line[line.find('<') + 1 : line.rfind('>')]
        sepPos = class_method.find(':')
        className = class_method[0 : sepPos].strip()
          
        methodStr = class_method[sepPos + 1 :].strip()
        methodName, params, returnValue = parseMethod(methodStr)
          
        modParStr = ""
        for par in params:
            if par != "":
                modParStr += transformClassParam(par) + ' '
        modParStr = modParStr.strip()
         
        method_identificator = "%s-%s-(%s)%s" % (transformClassParam(className), methodName, modParStr, transformClassParam(returnValue))
         
        try:
            methods_mapping[method_identificator].add(perm_name)
        except KeyError:
            methods_mapping[method_identificator] = set()
            methods_mapping[method_identificator].add(perm_name)



print "Reading contentproviderfield mapping file..."    
pscout_contentproviderfields_mapping_filepath = os.path.join(PATH_TO_PSCOUT_FOLDER, PSCOUT_CONTENTPROVIDERFIELDS_MAPPING_FILENAME)
contentproviderfields_mapping_file_lines = []
with open(pscout_contentproviderfields_mapping_filepath, 'r') as pscout_file:
    contentproviderfields_mapping_file_lines = pscout_file.readlines()
    
perm_name = None
fields_mapping = {}
for line in contentproviderfields_mapping_file_lines:
    line = line.strip()
    if line.startswith("PERMISSION:"):
        perm_name = line.split("PERMISSION:")[1].strip()
        print "PROCESSING PERMISSIONS: %s" % perm_name
    elif line.startswith("<"):
        field_entry = line[line.find('<') + 1 : line.rfind('>')]
        classNameSepPos = field_entry.find(':')
        className = field_entry[0 : classNameSepPos].strip()
          
        proto_name_str = field_entry[classNameSepPos + 1 :].strip()
        proto_name_parts = proto_name_str.split()
        proto = proto_name_parts[0].strip()
        name = proto_name_parts[1].strip()
        
        field_identificator = "%s-%s-%s" % (transformClassParam(className), name, transformClassParam(proto))
         
        try:
            fields_mapping[field_identificator].add(perm_name)
        except KeyError:
            fields_mapping[field_identificator] = set()
            fields_mapping[field_identificator].add(perm_name)



print "Appending found information to the mappings file..."
with codecs.open(api_specific_mappings_module_path, 'w', 'utf-8') as perm_py_module:
    perm_py_module.write('#!/usr/bin/python\n')
    perm_py_module.write('# -*- coding: %s -*-\n\n' % 'utf-8')
    
    perm_py_module.write('# This file is a part of Androguard.\n')
    perm_py_module.write('#\n')
    perm_py_module.write('# This file is generated automatically from the data\n') 
    perm_py_module.write('# provided by PScout tool [http://pscout.csl.toronto.edu/]\n')
    perm_py_module.write('# using script: %s\n' % os.path.basename(__file__))
    perm_py_module.write('#\n')
    perm_py_module.write('# Author: Yury Zhauniarovich\n')
    perm_py_module.write('#\n')
    perm_py_module.write('#\n')
    perm_py_module.write('# Licensed under the Apache License, Version 2.0 (the "License");\n')
    perm_py_module.write('# you may not use this file except in compliance with the License.\n')
    perm_py_module.write('# You may obtain a copy of the License at\n')
    perm_py_module.write('#\n')
    perm_py_module.write('#      http://www.apache.org/licenses/LICENSE-2.0\n')
    perm_py_module.write('#\n')
    perm_py_module.write('# Unless required by applicable law or agreed to in writing, software\n')
    perm_py_module.write('# distributed under the License is distributed on an "AS-IS" BASIS,\n')
    perm_py_module.write('# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n')
    perm_py_module.write('# See the License for the specific language governing permissions and\n')
    perm_py_module.write('# limitations under the License"\n\n')
    
    perm_py_module.write('#################################################\n')
    perm_py_module.write('### API version: %d \n' % API_VERSION)
    perm_py_module.write('#################################################\n\n\n') 
     
    perm_py_module.write("%s = {\n" % METHODS_MAPPING_PARAM_NAME)
    for method in methods_mapping.keys():
        permissions = methods_mapping.get(method)
        perms_string = ", ".join(["'%s'" % prm for prm in permissions])
        perm_py_module.write("\t'%s' : [%s],\n" % (method, perms_string))
    perm_py_module.write("}\n\n")
 
    perm_py_module.write("%s = {\n" % FIELDS_MAPPING_PARAM_NAME)
    for field in fields_mapping.keys():
        permissions = fields_mapping.get(field)
        perms_string = ", ".join(["'%s'" % prm for prm in permissions])
        perm_py_module.write("\t'%s' : [%s],\n" % (field, perms_string))
    perm_py_module.write("}\n")
    perm_py_module.write("#################################################\n")
     
     
 
print "Done..."