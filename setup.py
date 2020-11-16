#!/usr/bin/env python3
"""Setup for MobSF."""


from setuptools import (
    find_packages,
    setup,
)

from pathlib import Path


def read(rel_path):
    init = Path(__file__).resolve().parent / rel_path
    return init.read_text('utf-8', 'ignore')


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('MOBSF_VER'):
            return line.split('\'')[1]
    raise RuntimeError('Unable to find version string.')


description = (
    'Mobile Security Framework (MobSF) is an automated,'
    ' all-in-one mobile application (Android/iOS/Windows) pen-testing,'
    ' malware analysis and security assessment framework capable of '
    'performing static and dynamic analysis.')
setup(
    name='mobsf',
    version=get_version('MobSF/settings.py'),
    description=description,
    author='Ajin Abraham',
    author_email='ajin25@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        ('License :: OSI Approved :: '
         'GNU General Public License v3 (GPLv3)',),
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
    ],
    packages=find_packages(include=[
        'MobSF', 'MobSF.*',
        'MalwareAnalyzer', 'MalwareAnalyzer.*',
        'DynamicAnalyzer', 'DynamicAnalyzer.*',
        'StaticAnalyzer', 'StaticAnalyzer.*',
    ]),
    python_requires='>=3.7<3.9',
    include_package_data=True,
    url='https://github.com/MobSF/Mobile-Security-Framework-MobSF',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    install_requires=Path('requirements.txt').read_text().splitlines(),
)
