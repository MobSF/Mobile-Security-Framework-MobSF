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




import os, re, codecs
from xml.dom import minidom
from xml.parsers.expat import ExpatError


PATH_TO_AOSP_ROOT = "" #path to AOSP folder

AOSP_PERMISSION_MODULE_NAME = "aosp_permissions"
AOSP_PERMISSION_MODULE_PATH = "../../androguard/core/api_specific_resources/aosp_permissions/"    #where to append the results

SDK_VERSION_PATTERN = re.compile("\s*PLATFORM_SDK_VERSION\s*:=\s*(?P<sdk_version>\d{1,3})\s*") #hope Android will get 3digit version number :)
PLATFORM_VERSION_PATTERN = re.compile("\s*PLATFORM_VERSION\s*:=\s*(?P<platform_version>.+)\s*")        #just to add as a comment from which version the parsing has happened

ANDROID_MANIFEST_NAME = "AndroidManifest.xml"
STRINGS_REL_PATH = "res/values/strings.xml"
PLATFORM_VERSIONS_FILE_REL_PATH = "build/core/version_defaults.mk"
NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"

AOSP_PERMISSIONS_PARAM_NAME = "AOSP_PERMISSIONS"
AOSP_PERMISSION_GROUPS_PARAM_NAME = "AOSP_PERMISSION_GROUPS"


def getPlatformVersions(aosp_root_dir):
    sdk_version = None
    platform_version = None
    version_file_path = os.path.join(aosp_root_dir, PLATFORM_VERSIONS_FILE_REL_PATH)
    if os.path.isfile(version_file_path):
        with open(version_file_path, 'r') as ver_file:
            lines = ver_file.readlines()
            for line in lines:
                sdk_version_match = SDK_VERSION_PATTERN.match(line)
                if sdk_version_match:
                    sdk_version = sdk_version_match.group('sdk_version')
                    continue
                platform_version_match = PLATFORM_VERSION_PATTERN.match(line)
                if platform_version_match:
                    platform_version = platform_version_match.group('platform_version')
                    continue
    return platform_version, sdk_version
    

def get_all_dirs_with_manifest(root_dir_path):
    dir_list = list()
    for root, dirs, files in os.walk(root_dir_path):
        for name in files:
            if name == ANDROID_MANIFEST_NAME:
                dir_list.append(root)
    return dir_list


def get_permission_details(manifest_dir):
    perms = {}
    perm_groups = {}
    
    dstrings = {}
    strings_document = None
    strings_document_path = os.path.join(manifest_dir, STRINGS_REL_PATH) 
    if os.path.exists(strings_document_path):
        print "Parsing file: %s" % strings_document_path
        strings_document = None
        try:
            strings_document = minidom.parse(strings_document_path)
        except ExpatError: 
            with open(strings_document_path, 'r') as xml_file:
                xml_string = xml_file.read()
                xml_string = xml_string[xml_string.find('<?xml version="1.0" encoding="utf-8"?>'):]
                strings_document = minidom.parseString(xml_string)      
        
        #loading strings into memory
        dstrings = {}
        for i in strings_document.getElementsByTagName("string"):
            try:
                dstrings[i.getAttribute("name")] = i.firstChild.data
            except AttributeError:
                pass
        
    
    
    manifest_path = os.path.join(manifest_dir, ANDROID_MANIFEST_NAME)
    print "Working with file: %s" % manifest_path
    #getting permissions
    manifest_document = None
    try:
        manifest_document = minidom.parse(manifest_path)
    except ExpatError: 
        with open(manifest_path, 'r') as xml_file:
            xml_string = xml_file.read()
            xml_string = xml_string[xml_string.find('<?xml version="1.0" encoding="utf-8"?>'):]
            manifest_document = minidom.parseString(xml_string)      
        
    for i in manifest_document.getElementsByTagName("permission"):
        name = i.getAttributeNS(NS_ANDROID_URI, "name")
        protection_level = i.getAttributeNS(NS_ANDROID_URI, "protectionLevel")
        permission_group = i.getAttributeNS(NS_ANDROID_URI, "permissionGroup")
        
     
        label = ""
        label_string_id = i.getAttributeNS(NS_ANDROID_URI, "label")[8:]
        if label_string_id != "":
            label = dstrings.get(label_string_id, "")
        
        description = ""
        description_string_id = i.getAttributeNS( NS_ANDROID_URI, "description" )[8:]
        if description_string_id !="":
            description = dstrings.get(description_string_id, "")
        
        #removing auxiliary symbols
        label = ' '.join(label.split())
        description = ' '.join(description.split())
        
        perms[name] = {"label": label, "description": description, "protectionLevel": protection_level, "permissionGroup": permission_group}
    
    
    #getting permission groups
    for i in manifest_document.getElementsByTagName("permission-group"):
        name = i.getAttributeNS(NS_ANDROID_URI, "name")
        
        label = ""
        label_string_id = i.getAttributeNS(NS_ANDROID_URI, "label")[8:]
        if label_string_id != "":
            label = dstrings.get(label_string_id, "")
        
        description = ""
        description_string_id = i.getAttributeNS( NS_ANDROID_URI, "description" )[8:]
        if description_string_id !="":
            description = dstrings.get(description_string_id, "")
        
                #removing auxiliary symbols
        label = ' '.join(label.split())
        description = ' '.join(description.split())
        perm_groups[name] = {"label": label, "description": description}
            
    return perms, perm_groups




print "Starting analysis [%s] ..." % PATH_TO_AOSP_ROOT

platform_version, sdk_version = getPlatformVersions(aosp_root_dir=PATH_TO_AOSP_ROOT)
print "Detected sdk_version [%s], platform_version [%s]..." % (platform_version, sdk_version)
if sdk_version == None:
    print "Cannot detect SDK version. Exiting!"
    exit(1)

print "Checking if we already have the file with the version..."
perms_module_name = "%s_api%s.py" % (AOSP_PERMISSION_MODULE_NAME, sdk_version)
perms_module_path = os.path.join(AOSP_PERMISSION_MODULE_PATH, perms_module_name)
if os.path.exists(perms_module_path):
    print "API specific file for this version already exists!"
    print "If you want create a file for newer version, please, delete file: %s" % perms_module_path
    exit(1)
    

permissions = {}
permission_groups = {}
 
print "Searching aosp for all manifest files..."
dirs_with_manifest = get_all_dirs_with_manifest(root_dir_path=PATH_TO_AOSP_ROOT)
for m_dir in dirs_with_manifest:
    perms, perm_groups = get_permission_details(m_dir)
    if perms:
        permissions.update(perms)
    if perm_groups:
        permission_groups.update(perm_groups)
     
 
 
#print "Permission:\n", permissions
#print "Permission Groups:\n", permission_groups
 
print "Checking if folder exists..."
if not os.path.exists(AOSP_PERMISSION_MODULE_PATH):
    os.makedirs(AOSP_PERMISSION_MODULE_PATH)
 
print "Appending found information to the permission file..."
with codecs.open(perms_module_path, 'w', 'utf-8') as perm_py_module:
    perm_py_module.write("#!/usr/bin/python\n")
    perm_py_module.write("# -*- coding: %s -*-\n" % "utf-8")
    perm_py_module.write("#################################################\n")
    perm_py_module.write("### Extracted from platform version: %s \n" % platform_version)
    perm_py_module.write("#################################################\n")
     
     
    perm_py_module.write("%s = {\n" % AOSP_PERMISSIONS_PARAM_NAME)
    for p_key in permissions.keys():
        properties = permissions.get(p_key)
        props_string = ", ".join(["'%s' : '%s'" % (prop_key, properties.get(prop_key)) for prop_key in properties.keys()])
        perm_py_module.write("\t'%s' : {%s},\n" % (p_key, props_string))
    perm_py_module.write("}\n\n")
 
    perm_py_module.write("%s = {\n" % AOSP_PERMISSION_GROUPS_PARAM_NAME)
    for pg_key in permission_groups.keys():
        properties = permission_groups.get(pg_key)
        props_string = ", ".join(["'%s' : '%s'" % (prop_key, properties.get(prop_key)) for prop_key in properties.keys()])
        perm_py_module.write("\t'%s' : {%s},\n" % (pg_key, props_string))
    perm_py_module.write("}\n")
    perm_py_module.write("#################################################\n")
     
     
 
 
print "Done..."
