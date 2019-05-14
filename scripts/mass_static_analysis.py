#!/usr/bin/env python
# Mass Static Analysis
import os
import urllib.request
import urllib.error
import urllib.parse
import argparse
import requests
import logging
logger = logging.getLogger(__name__)


def is_server_up(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.URLError:
        pass
    return False


def start_scan(directory, server_url, apikey, rescan='0'):
    print("\nLooking for Android/iOS/Windows binaries or source code in : " + directory)
    logger.info("Uploading to MobSF Server")
    uploaded = []
    MIME = {
        ".apk": 'application/octet-stream',
        ".ipa": 'application/octet-stream',
        ".appx": 'application/octet-stream',
        ".zip": 'application/zip'
    }
    for filename in os.listdir(directory):
        fpath = os.path.join(directory, filename)
        _, ext = os.path.splitext(fpath)
        if ext in MIME:
            files = {'file': (filename, open(fpath, 'rb'),
                              MIME[ext], {'Expires': '0'})}
            response = requests.post(
                server_url + '/api/v1/upload', files=files, headers={'AUTHORIZATION': apikey})
            if response.status_code == 200 and "hash" in response.json():
                logger.info("[OK] Upload OK: " + filename)
                uploaded.append(response.json())
            else:
                logger.error("Performing Upload: " + filename)

    logger.info("Running Static Analysis")
    for upl in uploaded:
        logger.info("Started Static Analysis on: %s", upl["file_name"])
        if rescan == '1':
            upl["re_scan"] = 1
        response = requests.post(
            server_url + "/api/v1/scan", data=upl, headers={'AUTHORIZATION': apikey})
        if response.status_code == 200:
            logger.info("[OK] Static Analysis Complete: " + upl["file_name"])
        else:
            logger.error("Performing Static Analysis: " + upl["file_name"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory",
                        help="Path to the directory that contains mobile app binary/zipped source code")
    parser.add_argument(
        "-s", "--ipport", help="IP address and Port number of a running MobSF Server. (ex: 127.0.0.1:8000)")
    parser.add_argument(
        "-k", "--apikey", help="MobSF REST API Key")
    parser.add_argument(
        "-r", "--rescan", help="Run a fresh scan. Value can be 1 or 0 (Default: 0)")
    args = parser.parse_args()

    if args.directory and args.ipport and args.apikey:
        server = args.ipport
        directory = args.directory
        server_url = "http://" + server
        apikey = args.apikey
        rescan = args.rescan
        if is_server_up(server_url) == False:
            print("MobSF REST API Server is not running at " + server_url)
            print("Exiting!")
            exit(0)
        # MobSF is running, start scan
        start_scan(directory, server_url, apikey, rescan)
    else:
        parser.print_help()
