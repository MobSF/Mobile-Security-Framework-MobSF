#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = 'androguard',
    version = '3.0',
    packages = find_packages(),
    scripts = ['androaxml.py', 'androcsign.py', 'androdiff.py', 'androgexf.py',
               'androlyze.py', 'androsign.py', 'androsim.py', 'apkviewer.py',
               'androdd.py', 'androgui.py',
               ],
    install_requires=['distribute'],
)
