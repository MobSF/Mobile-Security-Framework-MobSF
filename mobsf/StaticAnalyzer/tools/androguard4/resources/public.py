# -*- coding: utf_8 -*-
# flake8: noqa
import os
from xml.dom import minidom

_public_res = None
# copy the newest sdk/platforms/android-?/data/res/values/public.xml here
if _public_res is None:
    _public_res = {}
    root = os.path.dirname(os.path.realpath(__file__))
    xmlfile = os.path.join(root, "public.xml")
    if os.path.isfile(xmlfile):
        with open(xmlfile, "r") as fp:
            _xml = minidom.parseString(fp.read())
            for element in _xml.getElementsByTagName("public"):
                _type = element.getAttribute('type')
                _name = element.getAttribute('name')
                _id = int(element.getAttribute('id'), 16)
                if _type not in _public_res:
                    _public_res[_type] = {}
                _public_res[_type][_name] = _id
    else:
        raise Exception("need to copy the sdk/platforms/android-?/data/res/values/public.xml here")

SYSTEM_RESOURCES = {
    "attributes": {
        "forward": {k: v for k, v in _public_res['attr'].items()},
        "inverse": {v: k for k, v in _public_res['attr'].items()}
    },
    "styles": {
        "forward": {k: v for k, v in _public_res['style'].items()},
        "inverse": {v: k for k, v in _public_res['style'].items()}
    }
}
