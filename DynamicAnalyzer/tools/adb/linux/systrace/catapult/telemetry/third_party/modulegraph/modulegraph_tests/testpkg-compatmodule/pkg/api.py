""" pkg.api """

import sys

if sys.version_info[0] == 2:
    from .api2 import *

else:
    from .api3 import *
