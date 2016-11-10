#!/usr/bin/env python
# Mass Static Analysis
import tornado.httpclient
import os
import urllib2
import argparse
import mimetypes
import re
import json
import hashlib
import urllib
from threading import Thread


def HTTP_GET_Request(url):
    response = None
    http_client = tornado.httpclient.HTTPClient()
    try:
        response = http_client.fetch(url)
    except tornado.httpclient.HTTPError as e:
        pass
    except Exception as e:
        print("[ERROR] HTTP GET Request Error: " + str(e))
    http_client.close()
    return response


def isServerUp(url):
    try:
        response = urllib2.urlopen(url, timeout=5)
        return True
    except urllib2.URLError:
        pass
    return False


def getCSRF(url):
    resp = HTTP_GET_Request(url)
    return resp.headers['Set-Cookie'].split(";")[0].split("=")[1]


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append(
            'Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def genMD5(app):

    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(app, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while buf:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return (hasher.hexdigest())


def doScan(app, server_url):
    print "\nUploading : " + app
    UPLOAD_URL = server_url + "/upload/"
    CSRF = getCSRF(server_url)
    APP_NAME = os.path.basename(app)

    fields = [("csrfmiddlewaretoken", CSRF)]
    files = [("file", APP_NAME, open(app, "rb").read())]

    http_client = tornado.httpclient.HTTPClient()
    content_type, body = encode_multipart_formdata(fields, files)
    headers = {"Content-Type": content_type,
               'content-length': str(len(body)), 'Cookie': 'csrftoken=' + CSRF}
    request = tornado.httpclient.HTTPRequest(
        UPLOAD_URL, "POST", headers=headers, body=body, validate_cert=False)
    response = http_client.fetch(request)
    if response.code == 200:
        r = json.loads(response.body)
        if r["status"] == "success":
            MD5 = genMD5(app)
            SCAN_DB[MD5] = APP_NAME
            # Start Scan
            START_SCAN_URL = server_url + "/" + \
                r["url"].replace(APP_NAME, urllib.quote(APP_NAME))
            SCAN_URLS.append(START_SCAN_URL)
        elif r["description"]:
            print r["description"]
    return SCAN_DB, SCAN_URLS


def startScan(directory, server_url):
    SCAN_URLS = []
    SCAN_DB = {}
    print "\nLooking for Android/iOS binaries or source code in : " + directory
    for root, directories, filenames in os.walk(directory):
        for filename in filenames:
            scan_file = os.path.join(root, filename)
            abs_filename, file_extension = os.path.splitext(scan_file)
            if re.findall("apk|ipa|zip", file_extension):
                SCAN_DB, SCAN_URLS = doScan(scan_file, server_url)
    if len(SCAN_URLS) > 0:
        print "\nFiles Uploaded "
        print "======================================================================"
        print "MD5                              |             App                    "
        print "======================================================================"
        for key, val in SCAN_DB.items():
            print key + " | " + val
        print "\nInvoking Scan Request. This takes time depending on the number of apps to be scanned."
        for url in SCAN_URLS:
            t = Thread(target=HTTP_GET_Request, args=(url,))
            t.start()
        print "Please wait while MobSF is performing Static Analysis. Once the scan is completed, you can get the report by searching for the MD5 checksum"
        print "Exiting the Script..."

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--directory",
                    help="Path to the directory that contains mobile app binary/zipped source code")
parser.add_argument(
    "-s", "--ipport", help="IP address and Port number of a running MobSF Server. (ex: 127.0.0.1:8000)")

args = parser.parse_args()

SCAN_DB = dict()
SCAN_URLS = list()

if args.directory and args.ipport:
    SERVER = args.ipport
    DIRECTORY = args.directory
    SERVER_URL = "http://" + SERVER
    if isServerUp(SERVER_URL) == False:
        print "MobSF Server is not running at " + SERVER_URL
        print "Exiting....."
        exit(0)
    # MobSF is running, start scan
    startScan(DIRECTORY, SERVER_URL)
else:
    parser.print_help()
