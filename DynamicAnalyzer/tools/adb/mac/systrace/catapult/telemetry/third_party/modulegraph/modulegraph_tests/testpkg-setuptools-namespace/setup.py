from setuptools import setup

setup(
    name="nspkg",
    version="1.0",
    namespace_packages=['nspkg', 'nspkg.nssubpkg'],
    packages=['nspkg', 'nspkg.nssubpkg'],
    package_dir = {'': 'src'},
    zip_safe=False,
)
