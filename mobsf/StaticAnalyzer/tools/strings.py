import io


"""
Python Strings.

Strings-module to be independent from operating systems
Taken from: http://stackoverflow.com/a/17197027
"""


def strings_util(filename, minimum=6):
    """Print out all connected series of readable chars longer than minimum."""
    with io.open(filename, mode='rb') as f:
        result = ''
        for c in f.read().decode('utf-8', 'ignore'):
            if c in ('0123456789abcdefghijklmnopqrs'
                     'tuvwxyzABCDEFGHIJKLMNOPQRSTUV'
                     'WXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '):
                result += c
                continue
            if len(result) >= minimum and result[0].isalnum():
                yield '\'' + result + '\''
            result = ''
