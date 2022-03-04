import logging
import os 
import shutil
import urllib.request

import requests


logger = logging.getLogger(__name__)

JADX_URL='https://api.github.com/repos/skylot/jadx/releases/latest'

print('Installing Jadx')
logger.info('Installing Jadx')
response = requests.get(JADX_URL)
url = response.json()['assets'][0]['browser_download_url']
try:
    urllib.request.urlretrieve(url, './jadx.zip')
except Exception:
    logger.error('Failed to download Jadx')
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/'):
    shutil.rmtree('./mobsf/StaticAnalyzer/tools/jadx/')
os.makedirs('./mobsf/StaticAnalyzer/tools/jadx/')
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/'):
    print('Unpacking Jadx')
    shutil.unpack_archive('./jadx.zip','./mobsf/StaticAnalyzer/tools/jadx/')
os.remove('./jadx.zip')
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/bin/jadx'):
    os.chmod('./mobsf/StaticAnalyzer/tools/jadx/bin/jadx', 0o777)
