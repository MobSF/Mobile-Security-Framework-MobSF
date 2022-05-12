# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings
from django.utils import timezone

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.MobSF.utils import get_siphash, get_usergroups, sso_email
from mobsf.MobSF.views.helpers import FileType

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    logger.info('Adding to recent scan page, hash: %s', data['hash'])

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
                TIMESTAMP=timezone.now(),
                USER_APP_NAME=data['user_app_name'],
                USER_APP_VERSION=data['user_app_version'],
                DIVISION=data['division'],
                COUNTRY=data['country'],
                ENVIRONMENT=data['environment'],
                EMAIL=data['email'],
                USER_GROUPS=data['user_groups'])

            new_db_obj.save()
        else:
            scan = db_obj.first()
            if (not data['email'] in scan.EMAIL):
                scan.EMAIL = scan.EMAIL + ',' + data['email']
            if (not data['user_groups'] in scan.USER_GROUPS):
                scan.USER_GROUPS = scan.USER_GROUPS + ',' + data['user_groups']
            scan.FILE_NAME = data['file_name']
            scan.TIMESTAMP = timezone.now()
            scan.USER_APP_NAME = data['user_app_name']
            scan.USER_APP_VERSION = data['user_app_version']
            scan.DIVISION = data['division']
            scan.COUNTRY = data['country']
            scan.ENVIRONMENT = data['environment']
            scan.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, typ, source_content):
    """Write Uploaded File."""
    logger.info('Handling uploaded file')
    md5 = hashlib.md5()
    bfr = isinstance(content, io.BufferedReader)
    if bfr:
        logger.info('bfr is true')
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        logger.info('bfr is false')
        # File upload
        for chunk in content.chunks():
            md5.update(chunk)
    md5sum = md5.hexdigest()
    logger.info('Hash: %s', md5sum)
    local_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
    with open(local_dir + md5sum + typ, 'wb+') as destination:
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            for chunk in content.chunks():
                destination.write(chunk)
    if (source_content):
        logger.info('Processing source_content')
        bfr = isinstance(source_content, io.BufferedReader)
        with open(local_dir + md5sum + typ + '.src', 'wb+') as f:
            if bfr:
                logger.info('Source bfr is true')
                source_content.seek(0, 0)
                while chunk := source_content.read(8192):
                    f.write(chunk)
            else:
                logger.info('Source bfr is false')
                for chunk in source_content.chunks():
                    f.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name
        self.file_type = FileType(self.file)
        if ('source_file' in request.FILES):
            self.source_file = request.FILES['source_file']
            self.source_file_name = request.FILES['source_file'].name
        else:
            self.source_file = None
            self.source_file_name = None
        self.user_app_name = request.POST.get('user_app_name')
        self.user_app_version = request.POST.get('user_app_version')
        self.country = request.POST.get('country')
        self.division = request.POST.get('division')
        self.environment = request.POST.get('environment')
        self.email = sso_email(request)
        self.user_groups = get_usergroups(request)

    def scan_apk(self):
        """Android APK."""
        logger.info('Inside scan_apk, about to handle uploaded file.')
        md5 = handle_uploaded_file(self.file, '.apk', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'apk',
            'file_name': self.file_name,
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android APK')
        return data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'xapk',
            'file_name': self.file_name,
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android XAPK base APK')
        return data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'apks',
            'file_name': self.file_name,
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android Split APK')
        return data

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'zip',
            'file_name': self.file_name,
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Android/iOS Source Code')
        return data

    def scan_ipa(self):
        """IOS Binary."""
        md5 = handle_uploaded_file(self.file, '.ipa', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer_ios',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'ipa',
            'file_name': self.file_name,
            'status': 'success',
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of iOS IPA')
        return data

    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx', self.source_file)
        short_hash = get_siphash(md5)
        data = {
            'analyzer': 'static_analyzer_windows',
            'hash': md5,
            'short_hash': short_hash,
            'scan_type': 'appx',
            'file_name': self.file_name,
            'status': 'success',
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'country': self.country,
            'division': self.division,
            'environment': self.environment,
            'email': self.email,
            'user_groups': self.user_groups,
        }
        add_to_recent_scan(data)
        logger.info('Performing Static Analysis of Windows APP')
        return data
