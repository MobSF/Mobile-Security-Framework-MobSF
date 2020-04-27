```bash
git clone --recursive https://github.com/VirusTotal/yara-python
git checkout tags/v3.11.0
git submodule update --recursive
python3 setup.py bdist_wheel --python-tag cp36.cp37.cp38 --plat-name macosx-10.6-x86_64 build --enable-dex
python3 setup.py bdist_wheel --python-tag cp36.cp37.cp38 build --enable-dex
```