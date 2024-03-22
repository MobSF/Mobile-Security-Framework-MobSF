# -*- coding: utf_8 -*-
# flake8: noqa
# Type definiton for (type, data) tuples representing a value
# See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#262

# The 'data' is either 0 or 1, specifying this resource is either
# undefined or empty, respectively.
TYPE_NULL = 0x00
# The 'data' holds a ResTable_ref, a reference to another resource
# table entry.
TYPE_REFERENCE = 0x01
# The 'data' holds an attribute resource identifier.
TYPE_ATTRIBUTE = 0x02
# The 'data' holds an index into the containing resource table's
# global value string pool.
TYPE_STRING = 0x03
# The 'data' holds a single-precision floating point number.
TYPE_FLOAT = 0x04
# The 'data' holds a complex number encoding a dimension value
# such as "100in".
TYPE_DIMENSION = 0x05
# The 'data' holds a complex number encoding a fraction of a
# container.
TYPE_FRACTION = 0x06
# The 'data' holds a dynamic ResTable_ref, which needs to be
# resolved before it can be used like a TYPE_REFERENCE.
TYPE_DYNAMIC_REFERENCE = 0x07
# The 'data' holds an attribute resource identifier, which needs to be resolved
# before it can be used like a TYPE_ATTRIBUTE.
TYPE_DYNAMIC_ATTRIBUTE = 0x08
# Beginning of integer flavors...
TYPE_FIRST_INT = 0x10
# The 'data' is a raw integer value of the form n..n.
TYPE_INT_DEC = 0x10
# The 'data' is a raw integer value of the form 0xn..n.
TYPE_INT_HEX = 0x11
# The 'data' is either 0 or 1, for input "false" or "true" respectively.
TYPE_INT_BOOLEAN = 0x12
# Beginning of color integer flavors...
TYPE_FIRST_COLOR_INT = 0x1c
# The 'data' is a raw integer value of the form #aarrggbb.
TYPE_INT_COLOR_ARGB8 = 0x1c
# The 'data' is a raw integer value of the form #rrggbb.
TYPE_INT_COLOR_RGB8 = 0x1d
# The 'data' is a raw integer value of the form #argb.
TYPE_INT_COLOR_ARGB4 = 0x1e
# The 'data' is a raw integer value of the form #rgb.
TYPE_INT_COLOR_RGB4 = 0x1f
# ...end of integer flavors.
TYPE_LAST_COLOR_INT = 0x1f
# ...end of integer flavors.
TYPE_LAST_INT = 0x1f
