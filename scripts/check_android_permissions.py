#!/usr/bin/env python3

import re

import requests

from bs4 import BeautifulSoup as Soup

ANDROID_PERMISSION_DOCS_URL = ('https://developer.android.com/'
                               'reference/android/Manifest.permission')

response = requests.get(ANDROID_PERMISSION_DOCS_URL)
content = Soup(response.content, 'html.parser')

online_permissions = {}

# grab all the permissions from the online docs
permission_divs = content.find_all(
    'div', {'data-version-added': re.compile(r'\d*')})
for pd in permission_divs:
    permission_name = pd.find('h3').contents[0]
    if permission_name in ['Constants', 'Manifest.permission']:
        continue
    try:
        protection_level = re.search(
            r'Protection level\: (\w+)', str(pd)).groups()[0]
    except AttributeError:
        protection_level = 'normal'
    description = str(pd.find('p').contents[0]).strip()
    online_permissions[permission_name] = [protection_level,
                                           'TODO - fill in short description',
                                           description]

# check the permissions we currently have in dvm_permissions.py
DVM_PERMISSIONS = {}
eval(compile(open('StaticAnalyzer/views/android/dvm_permissions.py').read(),
             '<string>',
             'exec'))
MANIFEST_PERMISSIONS = DVM_PERMISSIONS['MANIFEST_PERMISSION']

for permission_name in online_permissions:
    if permission_name in MANIFEST_PERMISSIONS.keys():
        continue
    print('\'{}\': {},'.format(permission_name, str(
        online_permissions[permission_name])))
