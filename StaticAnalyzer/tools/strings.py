import io
"""
Strings-module to be undependend from operating systems
Taken from: http://stackoverflow.com/a/17197027
"""

def strings(filename, min=6):
    """Print out all connected series of readable chars longer than min."""
    with io.open(filename, mode="rb") as f:
        result = ""
        for c in f.read():
            if c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
                result += c
                continue
            if len(result) >= min and result[0].isalnum():
                yield "'" + result + "'"
            result = ""
