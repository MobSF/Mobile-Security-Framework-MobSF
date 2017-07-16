"""
Package structure simular to crcmod
"""
try:
    from pkg.pkg import *
    import pkg.base
except ImportError:
    from pkg import *
    import base
