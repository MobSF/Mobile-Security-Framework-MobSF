# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.MobSF.security import sanitize_filename
# Cyberspect imports begin
from mobsf.MobSF.views.helpers import FileType

from cyberspect.utils import (
    get_siphash,
    get_usergroups,
    is_admin,
    sso_email,
    utcnow,
)
# Cyberspect imports end

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        logger.info('Data received in add_to_recent_scan: %s', data)
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            # Cyberspect mods
            classification = data.get('data_privacy_classification', '')
            attributes = data.get('data_privacy_attributes', '')
            # End Cyberspect mods
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                MD5=data['hash'],
                TIMESTAMP=utcnow(),  # Begin Cyberspect mods
                USER_APP_NAME=data.get('user_app_name', ''),
                USER_APP_VERSION=data.get('user_app_version', ''),
                DIVISION=data.get('division', ''),
                ENVIRONMENT=data.get('environment', ''),
                COUNTRY=data.get('country', ''),
                EMAIL=data.get('email', ''),
                USER_GROUPS=data.get('user_groups', ''),
                RELEASE=data.get('release', False),
                DATA_PRIVACY_CLASSIFICATION=classification,
                DATA_PRIVACY_ATTRIBUTES=attributes)  # End Cyberspect mods
            new_db_obj.save()
        # Cyberspect mods
        else:
            # Cyberspect mods
            scan = db_obj.first()
            if data.get('email') and (data['email'] not in scan.EMAIL):
                scan.EMAIL = scan.EMAIL + ',' + data['email']
            if (not data['user_groups'] in scan.USER_GROUPS):
                scan.USER_GROUPS = (scan.USER_GROUPS + ','
                                    + data['user_groups'])
            scan.FILE_NAME = data['file_name']
            scan.TIMESTAMP = utcnow()
            scan.USER_APP_NAME = data.get('user_app_name', '')
            scan.USER_APP_VERSION = data.get('user_app_version', '')
            scan.DIVISION = data.get('division', '')
            scan.ENVIRONMENT = data.get('environment', '')
            scan.COUNTRY = data.get('country', '')
            scan.RELEASE = data.get('release', '')
            scan.DATA_PRIVACY_CLASSIFICATION = \
                data.get('data_privacy_classification', '')
            scan.DATA_PRIVACY_ATTRIBUTES = \
                data.get('data_privacy_attributes', '')
            scan.save()
    # End Cyberspect mods
    except Exception as ex:
        logger.exception('Adding Scan URL to Database')
        # Cyberspect mod
        raise ex
        # End Cyberspect mod


# Cyberspect mods begin
def handle_uploaded_file(content, extension, source_content=None):
    # Cyberspect mods end
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

    # Cyberspect mods begin (local development mode)
    if settings.LOCAL_DEV_MODE:
        # Ensure parent upload directory exists
        if not os.path.exists(settings.UPLD_DIR):
            try:
                os.makedirs(settings.UPLD_DIR, exist_ok=True)
            except Exception as e:
                msg = f'Failed to create upload directory {settings.UPLD_DIR}: {e}'
                logger.error(msg)
                raise

        if not os.path.exists(anal_dir):
            try:
                os.makedirs(anal_dir, exist_ok=True)
            except Exception as e:
                msg = f'Failed to create analysis directory {anal_dir}: {e}'
                logger.error(msg)
                raise

        # Validate directory was actually created
        if not os.path.exists(anal_dir):
            os.makedirs(anal_dir)
            raise Exception(f'Failed to create upload directory: {anal_dir}')

        file_path = f'{anal_dir}{md5sum}{extension}'

        try:
            with open(file_path, 'wb+') as destination:
                if bfr:
                    content.seek(0, 0)
                    while chunk := content.read(8192):
                        destination.write(chunk)
                else:
                    for chunk in content.chunks():
                        destination.write(chunk)

            # Validate file was actually written
            if not os.path.exists(file_path):
                raise Exception(f'Failed to write uploaded file: {file_path}')

        except Exception:
            raise
    else:
        # Cyberspect mods end (local development mode)
        if not os.path.exists(anal_dir):
            os.makedirs(anal_dir)
        with open(f'{anal_dir}{md5sum}{extension}', 'wb+') as destination:
            if bfr:
                content.seek(0, 0)
                while chunk := content.read(8192):
                    destination.write(chunk)
            else:
                for chunk in content.chunks():
                    destination.write(chunk)

    if (source_content):
        bfr = isinstance(source_content, io.BufferedReader)
        with open(f'{anal_dir}{md5sum}{extension}' + '.src', 'wb+') as f:
            if bfr:
                source_content.seek(0, 0)
                while chunk := source_content.read(8192):
                    f.write(chunk)
            else:
                for chunk in source_content.chunks():
                    f.write(chunk)
    # End Cyberspect mods
    return md5sum


class Scanning(object):

    def __init__(self, request):
        # Cyberspect mods
        if ('file' in request.FILES):
            self.file = request.FILES['file']
            self.file_name = sanitize_filename(
                request.FILES['file'].name)
            self.file_type = FileType(self.file)
            self.file_size = self.file.size
        else:
            self.file = None
            self.file_name = None
            self.file_type = None
            self.file_size = None
        if ('source_file' in request.FILES):
            self.source_file = request.FILES['source_file']
            self.source_file_name = self.source_file.name
            self.source_file_size = self.source_file.size
        else:
            self.source_file = None
            self.source_file_name = None
            self.source_file_size = None
        self.user_app_name = request.POST.get('user_app_name', '')
        self.user_app_version = request.POST.get('user_app_version', '')
        self.division = request.POST.get('division', '')
        self.environment = request.POST.get('environment', '')
        self.country = request.POST.get('country', '')
        self.data_privacy_classification = \
            request.POST.get('data_privacy_classification', '')
        self.data_privacy_attributes = \
            request.POST.get('data_privacy_attributes', '')
        self.email = sso_email(request)
        logger.info('Email from sso_email: %s', self.email)
        self.user_groups = get_usergroups(request)
        logger.info('User groups: %s', self.user_groups)
        self.release = False
        if (is_admin(request)):
            self.release = (request.POST.get('release', '') == 'true')
            if request.POST.get('email'):
                self.email = request.POST.get('email')
                logger.info('Admin override email: %s', self.email)
        self.rescan = request.POST.get('rescan', '0')
        self.cyberspect_scan_id = 0
        self.md5 = ''
        self.short_hash = ''
        self.scan_type = ''
        # Cyberspect mods end
        self.data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
            # Cyberspect additions begin
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'division': self.division,
            'environment': self.environment,
            'country': self.country,
            'data_privacy_classification': self.data_privacy_classification,
            'data_privacy_attributes': self.data_privacy_attributes,
            'email': self.email,
            'user_groups': self.user_groups,
            'release': self.release,
            # Cyberspect additions end
        }

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apk'
        # Cyberspect mods begin
        self.scan_type = 'apk'
        # Cyberspect mods END
        add_to_recent_scan(self.data)
        logger.info('Android APK uploaded')
        return self.data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'xapk'
        add_to_recent_scan(self.data)
        logger.info('Android XAPK uploaded')
        return self.data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apks'
        add_to_recent_scan(self.data)
        logger.info('Android Split APK uploaded')
        return self.data

    def scan_aab(self):
        """Android App Bundle."""
        md5 = handle_uploaded_file(self.file, '.aab')
        self.data['hash'] = md5
        self.data['scan_type'] = 'aab'
        add_to_recent_scan(self.data)
        logger.info('Android App Bundle uploaded')
        return self.data

    def scan_jar(self):
        """Java JAR file."""
        md5 = handle_uploaded_file(self.file, '.jar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'jar'
        add_to_recent_scan(self.data)
        logger.info('Java JAR uploaded')
        return self.data

    def scan_aar(self):
        """Android AAR file."""
        md5 = handle_uploaded_file(self.file, '.aar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'aar'
        add_to_recent_scan(self.data)
        logger.info('Android AAR uploaded')
        return self.data

    def scan_so(self):
        """Shared object file."""
        md5 = handle_uploaded_file(self.file, '.so')
        self.data['hash'] = md5
        self.data['scan_type'] = 'so'
        add_to_recent_scan(self.data)
        logger.info('Shared Object Library uploaded')
        return self.data

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        self.data['hash'] = md5
        self.data['scan_type'] = 'zip'
        add_to_recent_scan(self.data)
        logger.info('Android/iOS Source code ZIP uploaded')
        return self.data

    def scan_ipa(self):
        """IOS Binary."""
        logger.info('DEBUG: Scanning.scan_ipa method called')
        md5 = handle_uploaded_file(self.file, '.ipa')
        self.data['hash'] = md5
        self.data['scan_type'] = 'ipa'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('iOS IPA uploaded')
        return self.data

    def scan_dylib(self):
        """IOS Dylib."""
        md5 = handle_uploaded_file(self.file, '.dylib')
        self.data['hash'] = md5
        self.data['scan_type'] = 'dylib'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('iOS dylib uploaded')
        return self.data

    def scan_a(self):
        """Scan static library."""
        md5 = handle_uploaded_file(self.file, '.a')
        self.data['hash'] = md5
        self.data['scan_type'] = 'a'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('Static Library uploaded')
        return self.data

    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx')
        self.data['hash'] = md5
        self.data['scan_type'] = 'appx'
        self.data['analyzer'] = 'static_analyzer_windows'
        add_to_recent_scan(self.data)
        logger.info('Windows APPX uploaded')
        return self.data

    # Cyberspect add begins
    def populate_data_dict(self):
        """Cyberspect specific function: Populates the data dictionary."""
        self.md5 = handle_uploaded_file(self.file, '.' + self.scan_type,
                                        self.source_file)
        self.short_hash = get_siphash(self.md5)
        return {
            'analyzer': 'static_analyzer',
            'hash': self.md5,
            'short_hash': self.short_hash,
            'scan_type': self.scan_type,
            'file_name': self.file_name,
            'status': 'success',
            'user_app_name': self.user_app_name,
            'user_app_version': self.user_app_version,
            'division': self.division,
            'environment': self.environment,
            'country': self.country,
            'data_privacy_classification': self.data_privacy_classification,
            'data_privacy_attributes': self.data_privacy_attributes,
            'email': self.email,
            'user_groups': self.user_groups,
            'release': self.release,
            'cyberspect_scan_id': self.cyberspect_scan_id,
            'rescan': self.rescan,
        }
    # Cyberspect add begins
