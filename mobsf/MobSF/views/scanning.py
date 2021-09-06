# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings
from django.utils import timezone

from mobsf.StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                MD5=data['hash'],
                TIMESTAMP=timezone.now())
            new_db_obj.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, typ):
    """Write Uploaded File."""
    md5 = hashlib.md5()
    bfr = isinstance(content, io.BufferedReader)
    if bfr:
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # File upload
        for chunk in content.chunks():
            md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(anal_dir + md5sum + typ, 'wb+') as destination:
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            for chunk in content.chunks():
                destination.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'apk',
            'file_name': self.file_name,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android APK')
        return data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk')
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'xapk',
            'file_name': self.file_name,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android XAPK base APK')
        return data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'apks',
            'file_name': self.file_name,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android Split APK')
        return data

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'zip',
            'file_name': self.file_name,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android/iOS Source Code')
        return data

    def scan_ipa(self):
        """IOS Binary."""
        md5 = handle_uploaded_file(self.file, '.ipa')
        data = {
            'analyzer': 'static_analyzer_ios',
            'hash': md5,
            'scan_type': 'ipa',
            'file_name': self.file_name,
            'status': 'success',
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of iOS IPA')
        return data

    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx')
        data = {
            'analyzer': 'static_analyzer_windows',
            'hash': md5,
            'scan_type': 'appx',
            'file_name': self.file_name,
            'status': 'success',
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Windows APP')
        return data
