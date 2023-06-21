# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os

from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse

from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.common.shared_func import (
    unzip,
)
from mobsf.StaticAnalyzer.views.android.static_analyzer import (
    valid_source_code
)
from mobsf.MobSF.utils import is_zip_magic_local_file

logger = logging.getLogger(__name__)
HTTP_BAD_REQUEST = 400


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


def handle_uploaded_file(content, extension, istemp=False):
    """Write Uploaded File."""
    md5 = hashlib.md5()
    bfr = False
    if isinstance(content, io.BufferedReader):
        bfr = True
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # File upload
        with open(content, 'rb') as file_obj:
            for chunk in iter(lambda: file_obj.read(8192), b''):
                md5.update(chunk)
        # for chunk in content.chunks():
        # md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if istemp:
        anal_dir = os.path.join(settings.TEMP_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    else:
        if istemp:
            # Delete all files and directories in the temp directory recursively
            for root, dirs, files in os.walk(anal_dir, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except OSError as e:
                        logger.error('Error while deleting file in temp directory: %s', e)
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except OSError as e:
                        logger.error('Error while deleting directory in temp directory: %s', e)

    with open(f'{anal_dir}{md5sum}{extension}', 'wb+') as destination:
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            with open(content, 'rb') as file_obj:
                for chunk in iter(lambda: file_obj.read(8192), b''):
                    destination.write(chunk)
            # for chunk in content.chunks():
            #     destination.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name
        self.data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
        }

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apk'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android APK')
        return self.data

    def scan_xapk(self):
        """Android XAPK."""
        md5 = handle_uploaded_file(self.file, '.xapk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'xapk'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android XAPK base APK')
        return self.data

    def scan_apks(self):
        """Android Split APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        self.data['hash'] = md5
        self.data['scan_type'] = 'apks'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android Split APK')
        return self.data

    def scan_jar(self):
        """Java JAR file."""
        md5 = handle_uploaded_file(self.file, '.jar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'jar'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Java JAR')
        return self.data

    def scan_aar(self):
        """Android AAR file."""
        md5 = handle_uploaded_file(self.file, '.aar')
        self.data['hash'] = md5
        self.data['scan_type'] = 'aar'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android AAR')
        return self.data

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        self.data['hash'] = md5
        self.data['scan_type'] = 'zip'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Android/iOS Source Code')
        return self.data

    def scan_ipa(self):
        """IOS Binary."""
        md5 = handle_uploaded_file(self.file, '.ipa')
        self.data['hash'] = md5
        self.data['scan_type'] = 'ipa'
        self.data['analyzer'] = 'static_analyzer_ios'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of iOS IPA')
        return self.data

    def scan_appx(self):
        """Windows appx."""
        md5 = handle_uploaded_file(self.file, '.appx')
        self.data['hash'] = md5
        self.data['scan_type'] = 'appx'
        self.data['analyzer'] = 'static_analyzer_windows'
        add_to_recent_scan(self.data)
        logger.info('Performing Static Analysis of Windows APP')
        return self.data

    def scan_generic(self, file_path, extension, scan_type, message, analyzer=None):
        """Generic file."""
        md5 = handle_uploaded_file(file_path, extension)
        self.data['hash'] = md5
        self.data['scan_type'] = scan_type
        if analyzer:
            self.data['analyzer'] = analyzer
        add_to_recent_scan(self.data)
        logger.info(message)
        return self.data

    def scan_encrypted_zip(self, password=None):
        md5 = handle_uploaded_file(self.file, '.zip', istemp=True)
        temp_dir = os.path.join(settings.TEMP_DIR, md5 + '/')
        file = os.path.join(temp_dir, md5 + '.zip')
        files = unzip(file, temp_dir, password)
        pro_type, valid = valid_source_code(temp_dir)
        if valid:
            md5 = handle_uploaded_file(self.file, '.zip')
            self.data['hash'] = md5
            self.data['scan_type'] = 'zip'
            add_to_recent_scan(self.data)
            logger.info('Performing Static Analysis of Android/iOS Source Code')
            return self.data
        else:
            if len(files) == 0:
                error_message = "Error: No files extracted from the ZIP."
                error_response = {'error': error_message}
                return JsonResponse(error_response, status=HTTP_BAD_REQUEST)
            elif len(files) > 1:
                error_message = "Error: More than 1 file extracted from the ZIP."
                error_response = {'error': error_message}
                return JsonResponse(error_response, status=HTTP_BAD_REQUEST)
            else:
                allowed_file_types = ['.apk', '.apks', '.xapk', '.zip', '.ipa', '.appx', '.jar', '.aar']
                full_file_path = os.path.join(temp_dir, files[0])
                if os.path.exists(full_file_path):
                    if is_zip_magic_local_file(full_file_path) and full_file_path.lower().endswith(allowed_file_types):
                        logger.info('File format extracted from the ZIP is Supported!')
                        if full_file_path.lower().endswith('.apk'):
                            self.scan_generic(full_file_path, '.apk', 'apk', 'Performing Static Analysis of Android APK', analyzer=None)
                        elif full_file_path.lower().endswith('.apks'):
                            self.scan_generic(full_file_path, '.apk', 'apks', 'Performing Static Analysis of Android Split APK', analyzer=None)
                        elif full_file_path.lower().endswith('.xapk'):
                            self.scan_generic(full_file_path, '.xapk', 'xapk', 'Performing Static Analysis of Android XAPK base APK', analyzer=None)
                        elif full_file_path.lower().endswith('.zip'):
                            self.scan_generic(full_file_path, '.zip', 'zip', 'Performing Static Analysis of Android/iOS Source Code', analyzer=None)
                        elif full_file_path.lower().endswith('.ipa'):
                            self.scan_generic(full_file_path, '.ipa', 'ipa', 'Performing Static Analysis of iOS IPA', analyzer='static_analyzer_ios')
                        elif full_file_path.lower().endswith('.appx'):
                            self.scan_generic(full_file_path, '.appx', 'appx', 'Performing Static Analysis of Windows APP', analyzer='static_analyzer_windows')
                        elif full_file_path.lower().endswith('.jar'):
                            self.scan_generic(full_file_path, '.jar', 'jar', 'Performing Static Analysis of Java JAR', analyzer=None)
                        elif full_file_path.lower().endswith('.aar'):
                            self.scan_generic(full_file_path, '.aar', 'aar', 'Performing Static Analysis of Android AAR', analyzer=None)

                    else:
                        error_message = "Error: File format extracted from the ZIP is not Supported!"
                        error_response = {'error': error_message}
                        return JsonResponse(error_response, status=HTTP_BAD_REQUEST)
                else:
                    error_message = "Error: File does not exist."
                    error_response = {'error': error_message}
                    return JsonResponse(error_response, status=HTTP_BAD_REQUEST)
