"""
Base class from which hash types can be created.

Part of python-hashes by sangelone. See README and LICENSE.
"""

default_hashbits = 96

class hashtype(object):
    def __init__(self, value='', hashbits=default_hashbits, hash=None):
        "Relies on create_hash() provided by subclass"
        self.hashbits = hashbits
        if hash:
            self.hash = hash
        else:
            self.create_hash(value)

    def __trunc__(self):
        return self.hash

    def __str__(self):
        return str(self.hash)
    
    def __long__(self):
        return long(self.hash)

    def __float__(self):
        return float(self.hash)
        
    def __cmp__(self, other):
        if self.hash < long(other): return -1
        if self.hash > long(other): return 1
        return 0
    
    def hex(self):
        return hex(self.hash)

    def hamming_distance(self, other_hash):
        x = (self.hash ^ other_hash.hash) & ((1 << self.hashbits) - 1)
        tot = 0
        while x:
            tot += 1
            x &= x-1
        return tot
