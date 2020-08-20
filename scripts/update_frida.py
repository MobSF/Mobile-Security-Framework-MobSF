#!/usr/bin/env python
import requests

import lzma
import shutil


def get_latest_frida_binaries():
    r = requests.get('https://api.github.com/'
                     'repos/frida/frida/releases/latest')
    for item in r.json()['assets']:
        url = item['browser_download_url']
        if ('frida-server' in url and 'android' in url):
            download_file(url)


def download_file(url):
    fname = url.split('/')[-1]
    print(f'Downloading & Extracting - {fname}')
    base = '../DynamicAnalyzer/tools/onDevice/frida/'
    dwd_file = fname.replace('.xz', '')
    dwd_loc = f'{base}{dwd_file}'
    with requests.get(url, stream=True) as r:
        with lzma.LZMAFile(r.raw) as f:
            with open(dwd_loc, 'wb') as flip:
                shutil.copyfileobj(f, flip)


if __name__ == '__main__':
    get_latest_frida_binaries()
