
# from MobSF.views import handle_uploaded_file, add_to_recent_scan
import hashlib
import os
import logging
from django.conf import settings
from django.utils import timezone

from MobSF.utils import PrintException
from StaticAnalyzer.models import RecentScansDB
logger = logging.getLogger(__name__)


def add_to_recent_scan(name, md5, url):
    """
    Add Entry to Database under Recent Scan
    """
    try:
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                NAME=name, MD5=md5, URL=url, TS=timezone.now())
            new_db_obj.save()
    except:
        PrintException("[ERROR] Adding Scan URL to Database")


def handle_uploaded_file(filecnt, typ):
    """
    Write Uploaded File
    """
    md5 = hashlib.md5()  # modify if crash for large
    for chunk in filecnt.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(anal_dir + md5sum + typ, 'wb+') as destination:
        for chunk in filecnt.chunks():
            destination.write(chunk)
    return md5sum



class Scanning(object):

    def __init__(self, request):
        self.request = request
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name
    
    def scan_apk(self):
        """
        """
        # APK
        md5 = handle_uploaded_file(self.file, '.apk')
        data = {
            'url': 'StaticAnalyzer/?name={}&type=apk&checksum={}'.format(self.file_name, md5),
            'status': 'success',
            'hash': md5,
            'scan_type': 'apk',
            'file_name': self.file_name
        }
    
        add_to_recent_scan(self.file_name, md5, data['url'])

        logger.info("Performing Static Analysis of Android APK")
        return data

    def scan_zip(self):
        """
        """
        # Android /iOS Zipped Source
        md5 = handle_uploaded_file(self.file, '.zip')

        data = {
            'url': 'StaticAnalyzer/?name={}&type=zip&checksum={}'.format(self.file_name, md5),
            'status': 'success',
            'hash': md5,
            'scan_type': 'zip',
            'file_name': self.file_name
        }

        add_to_recent_scan(self.file_name, md5, data['url'])
        logger.info("Performing Static Analysis of Android/iOS Source Code")
        return data

    def scan_ipa(self):
        """
        iOS Binary
        """
        md5 = handle_uploaded_file(self.file, '.ipa')
        data = {
            'hash': md5,
            'scan_type': 'ipa',
            'file_name': self.file_name,
            'url': 'StaticAnalyzer_iOS/?name={}&type=ipa&checksum={}'.format(self.file_name, md5),
            'status': 'success'
        }

        add_to_recent_scan(self.file_name, md5, data['url'])
        logger.info("Performing Static Analysis of iOS IPA")
        return data

    def scan_appx(self):
        """
        """
        md5 = handle_uploaded_file(self.file, '.appx')
        data = {
            'hash': md5,
            'scan_type': 'appx',
            'file_name': self.file_name,
            'url': 'StaticAnalyzer_Windows/?name={}&type=appx&checksum={}'.format(self.file_name, md5),
            'status': 'success'
        }
        
        add_to_recent_scan(self.file_name, md5, data['url'])
        logger.info("Performing Static Analysis of Windows APP")
        return data
