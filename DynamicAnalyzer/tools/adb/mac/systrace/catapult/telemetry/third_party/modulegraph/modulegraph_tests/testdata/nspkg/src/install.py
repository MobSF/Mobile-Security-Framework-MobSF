#!/usr/bin/env python
"""
Script that will create a subdirectory one level up with two subdirs
with --single-version-externally-managed namespace packages.

Use this script with new versions of distribute and setuptools to ensure
that changes in the handling of this option don't break us.
"""
import pkg_resources
import subprocess
import os
import sys
import shutil

def main():
    r = pkg_resources.require('setuptools')[0]
    install_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "%s-%s"%(r.project_name, r.version))
    if os.path.exists(install_dir):
        print("Skip %s %s: already installed"%(r.project_name, r.version))

    else:
        os.mkdir(install_dir)
        os.mkdir(os.path.join(install_dir, "parent"))
        os.mkdir(os.path.join(install_dir, "child"))

        if os.path.exists('parent/build'):
            shutil.rmtree('parent/build')
        if os.path.exists('child/build'):
            shutil.rmtree('child/build')

        for subdir in ('parent', 'child'):
            p = subprocess.Popen([
                sys.executable,
                "setup.py",
                "install",
                 "--install-lib=%s/%s"%(install_dir, subdir),
                 "--single-version-externally-managed",
                 "--record", "files.txt"
            ],
            cwd=subdir)
            xit = p.wait()
            if xit != 0:
                print("ERROR: install failed")
                sys.exit(1)


            if os.path.exists('%s/files.txt'%(subdir,)):
                os.unlink('%s/files.txt'%(subdir,))


if __name__ == "__main__":
    main()
