#!/bin/sh
# Copyright 2007 Google Inc.
#  Licensed to PSF under a Contributor Agreement.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# Converts the python2 ipaddr files to python3 and runs the unit tests
# with both python versions.

mkdir -p 2to3output && \
cp -f *.py 2to3output && \
( cd 2to3output && 2to3 . | patch -p0 ) && \
py3version=$(python3 --version 2>&1) && \
echo -e "\nTesting with ${py3version}" && \
python3 2to3output/ipaddr_test.py && \
rm -r 2to3output && \
pyversion=$(python --version 2>&1) && \
echo -e "\nTesting with ${pyversion}" && \
./ipaddr_test.py
