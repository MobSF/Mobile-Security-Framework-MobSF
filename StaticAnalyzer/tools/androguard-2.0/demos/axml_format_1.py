#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import apk
from androguard.util import read


from xml.dom import minidom

ap = apk.AXMLPrinter( read("examples/axml/AndroidManifest2.xml", binary=False) )

print minidom.parseString( ap.getBuff() ).toxml()
