#!/usr/bin/env python
import requests

import lzma
import shutil


def get_latest_frida_binaries():
    r = requests.get('https://api.github.com/'
                     'repos/frida/frida/releases/latest')
    for item in r.json()['assets']:
        url = item['browser_download_url']
        if ('frida-server' in url
                and 'android' in url
                and 'x86_64.xz' not in url):
            download_file(url)


def download_file(url):
    fname = url.split('/')[-1]
    print(f'Downloading & Extracting - {fname}')
    dwd = '../DynamicAnalyzer/tools/onDevice/frida/'
    with requests.get(url, stream=True) as r:
        with lzma.LZMAFile(r.raw) as f:
            dwd_file = fname.replace('.xz', '')
            dwd_loc = f'{dwd}{dwd_file}'
            with open(dwd_loc, 'wb') as flip:
                shutil.copyfileobj(f, flip)


if __name__ == '__main__':
    get_latest_frida_binaries()
