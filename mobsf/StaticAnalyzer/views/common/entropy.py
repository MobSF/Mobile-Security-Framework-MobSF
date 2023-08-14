
# -*- coding: utf_8 -*-
"""Entropy Scanner."""
import re
import math

MAX_LENGTH = 21
ENTROPY_PATTERNS = [
    {
        # Base64
        'pattern': re.compile(r'(?m)[a-zA-Z\d+/=]{20,}'),
        'charset': ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
                    'ghijklmnopqrstuvwxyz0123456789+/='),
        'score': 4.5,
    },
    {
        # Hex
        'pattern': re.compile(r'(?m)[a-fA-F\d-]{20,}'),
        'charset': '1234567890abcdefABCDEF',
        'score': 3.0,
    },
]


def entropy(data, charset):
    """Shannon Entropy score calculations."""
    # Based on
    # http://blog.dkbza.org/2007/05/
    # scanning-data-for-entropy-anomalies.html
    entropy = 0
    for char in charset:
        p_x = float(data.count(char)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def exclude(secret):
    """Exclude entropies."""
    excludes = ('abcdefghi', 'kotlin/')
    if secret.startswith('L') and '/' in secret:
        return True
    if any(i in secret.lower() for i in excludes):
        return True
    if secret.count('/') > 1:
        # URLs/paths, ignore them
        return True
    if secret.isalpha():
        return True
    return False


def get_entropies(data):
    patterns = set()
    for ascii_string in data:
        if len(ascii_string) < MAX_LENGTH:
            continue
        for p in ENTROPY_PATTERNS:
            for i in re.findall(p['pattern'], ascii_string):
                score = p['score']
                if entropy(i, p['charset']) > score and not exclude(i):
                    patterns.add(i)
    return patterns
