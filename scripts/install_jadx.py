import json
import logging
import os 
import requests
import shutil
import urllib.request

logger = logging.getLogger(__name__)

print('Installing Jadx')
logger.info('Installing Jadx')
response = requests.get("https://api.github.com/repos/skylot/jadx/releases/latest")
url = response.json()["assets"][0]["browser_download_url"]
try:
    urllib.request.urlretrieve(url, './jadx.zip')
except:
    logger.error( "Failed to download '{}'".format(url))
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/'):
    shutil.rmtree('./mobsf/StaticAnalyzer/tools/jadx/')
os.makedirs('./mobsf/StaticAnalyzer/tools/jadx/')
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/'):
    print('Unpacking Jadx')
    shutil.unpack_archive('./jadx.zip','./mobsf/StaticAnalyzer/tools/jadx/' )
os.remove('./jadx.zip')
if os.path.exists('./mobsf/StaticAnalyzer/tools/jadx/bin/jadx'):
    os.chmod('./mobsf/StaticAnalyzer/tools/jadx/bin/jadx', 0o777)
