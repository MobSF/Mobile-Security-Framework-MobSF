# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import datetime
import json
import logging
import os
import platform
import re
import shutil
import traceback as tb
from pathlib import Path
from wsgiref.util import FileWrapper

import boto3

from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import (
    redirect,
    render,
)
from django.template.defaulttags import register
from django.forms.models import model_to_dict
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.forms import FormUtil, UploadFileForm
from mobsf.MobSF.utils import (
    api_key,
    error_response,
    get_siphash,
    is_admin,
    is_dir_exists,
    is_file_exists,
    is_safe_path,
    key,
    sso_email,
    tz,
    utcnow,
)
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    CyberspectScans,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.common import appsec

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
logger = logging.getLogger(__name__)
register.filter('key', key)


def index(request):
    """Index Route."""
    mimes = (settings.APK_MIME
             + settings.IPA_MIME
             + settings.ZIP_MIME
             + settings.APPX_MIME)
    context = {
        'title': 'Cyberspect: Upload App',
        'version': settings.MOBSF_VER,
        'mimes': mimes,
        'is_admin': is_admin(request),
        'email': sso_email(request),
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/home2.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.scan = Scanning(self.request)

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        return resp

    def upload_html(self):
        logger.info('File uploaded via web UI by user %s',
                    sso_email(self.request))
        try:
            request = self.request
            response_data = {
                'description': '',
                'status': 'error',
            }
            if request.method != 'POST':
                msg = 'Method not Supported!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.form.is_valid():
                msg = 'Invalid Form Data!'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if not self.scan.file_type.is_allow_file():
                msg = 'File format not supported: ' \
                    + self.scan.file.content_type
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

            if self.scan.file_type.is_ipa():
                if platform.system() not in LINUX_PLATFORM:
                    msg = 'Static Analysis of iOS IPA requires Mac or Linux'
                    logger.error(msg)
                    response_data['description'] = msg
                    return self.resp_json(response_data)

            start_time = utcnow()
            response_data = self.upload()
            self.scan.cyberspect_scan_id = \
                new_cyberspect_scan(False, response_data['hash'],
                                    start_time,
                                    self.scan.file_size,
                                    self.scan.source_file_size,
                                    sso_email(self.request))
            cyberspect_scan_intake(self.scan.populate_data_dict())
            return self.resp_json(response_data)
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            msg = str(exp)
            exp_doc = exp.__doc__
            self.track_failure(msg)
            return error_response(request, msg, True, exp_doc)

    def upload_api(self):
        """API File Upload."""
        logger.info('Uploading through API')
        api_response = {}
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        if not self.scan.email:
            api_response['error'] = 'User email address not set'
            return api_response, HTTP_BAD_REQUEST
        if not self.scan.file_type.is_allow_file():
            api_response['error'] = 'File format not supported!'
            return api_response, HTTP_BAD_REQUEST
        start_time = utcnow()
        api_response = self.upload()
        self.scan.cyberspect_scan_id = \
            new_cyberspect_scan(False, api_response['hash'],
                                start_time,
                                self.scan.file_size,
                                self.scan.source_file_size,
                                sso_email(self.request))
        api_response['cyberspect_scan_id'] = self.scan.cyberspect_scan_id
        cyberspect_scan_intake(self.scan.populate_data_dict())
        return api_response, 200

    def upload(self):
        self.scan.rescan = '0'
        content_type = self.scan.file.content_type
        file_name = self.scan.file.name
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.scan.file_type.is_apk():
            return self.scan.scan_apk()
        elif self.scan.file_type.is_xapk():
            return self.scan.scan_xapk()
        elif self.scan.file_type.is_apks():
            return self.scan.scan_apks()
        elif self.scan.file_type.is_jar():
            return self.scan.scan_jar()
        elif self.scan.file_type.is_aar():
            return self.scan.scan_aar()
        elif self.scan.file_type.is_so():
            return self.scan.scan_so()
        elif self.scan.file_type.is_zip():
            return self.scan.scan_zip()
        elif self.scan.file_type.is_ipa():
            return self.scan.scan_ipa()
        elif self.scan.file_type.is_dylib():
            return self.scan.scan_dylib()
        elif self.scan.file_type.is_a():
            return self.scan.scan_a()
        elif self.scan.file_type.is_appx():
            return self.scan.scan_appx()

    def track_failure(self, error_message):
        if self.scan.cyberspect_scan_id == 0:
            return
        data = {
            'id': self.scan.cyberspect_scan_id,
            'success': False,
            'failure_source': 'SAST',
            'failure_message': error_message,
            'sast_end': utcnow(),
        }
        update_cyberspect_scan(data)


def api_docs(request):
    """Api Docs Route."""
    if (not is_admin(request)):
        return error_response(request, 'Unauthorized')

    context = {
        'title': 'REST API Docs',
        'api_key': api_key(),
        'version': settings.MOBSF_VER,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def support(request):
    """Support Route."""
    context = {
        'title': 'Support',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/support.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/about.html'
    return render(request, template, context)


def donate(request):
    """Donate Route."""
    context = {
        'title': 'Donate',
        'version': settings.MOBSF_VER,
    }
    template = 'general/donate.html'
    return render(request, template, context)


def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBSF_VER,
        'is_admin': is_admin(request),
    }
    template = 'general/zip.html'
    return render(request, template, context)


def not_found(request):
    """Not Found Route."""
    context = {
        'title': 'Not Found',
        'version': settings.MOBSF_VER,
    }
    template = 'general/not_found.html'
    return render(request, template, context)


def recent_scans(request):
    """Show Recent Scans Route."""
    entries = []
    sfilter = request.GET.get('filter', '')
    if sfilter:
        if re.match('[0-9a-f]{32}', sfilter):
            db_obj = RecentScansDB.objects.filter(MD5=sfilter)
        else:
            db_obj = RecentScansDB.objects \
                .filter(Q(APP_NAME__icontains=sfilter)
                        | Q(USER_APP_NAME__icontains=sfilter))
    else:
        db_obj = RecentScansDB.objects.all()
    db_obj = db_obj.order_by('-TIMESTAMP')[:100]
    isadmin = is_admin(request)
    if (not isadmin):
        email_filter = sso_email(request)
        if (not email_filter):
            email_filter = '@@'
        db_obj = db_obj.filter(EMAIL__contains=email_filter)

    recentscans = db_obj.values()
    android = StaticAnalyzerAndroid.objects.all()
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
    for entry in recentscans:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        logcat = Path(settings.UPLD_DIR) / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = logcat.exists()
        entry['CAN_RELEASE'] = (utcnow()
                                < entry['TIMESTAMP']
                                + datetime.timedelta(days=30))
        item = CyberspectScans.objects.filter(MOBSF_MD5=entry['MD5']).last()
        if item:
            entry['DT_PROJECT_ID'] = item.DT_PROJECT_ID
            entry['COMPLETE'] = item.SAST_END
            if (item.FAILURE_SOURCE == 'SAST'):
                entry['ERROR'] = item.FAILURE_MESSAGE
            else:
                entry['ERROR'] = None
        else:
            entry['DT_PROJECT_ID'] = None
            entry['COMPLETE'] = entry['TIMESTAMP']
            entry['ERROR'] = 'Unable to find cyberspect_scans record'
        entries.append(entry)
    context = {
        'title': 'Scanned Apps',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'is_admin': isadmin,
        'dependency_track_url': settings.DEPENDENCY_TRACK_URL,
        'filter': filter,
        'tenant_static': settings.TENANT_STATIC_URL,
    }
    template = 'general/recent.html'
    return render(request, template, context)


def scan_metadata(md5):
    """Get scan metadata."""
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            return model_to_dict(db_obj)
    return None


def get_cyberspect_scan(csid):
    db_obj = CyberspectScans.objects.filter(ID=csid).first()
    if db_obj:
        cs_obj = model_to_dict(db_obj)
        rs_obj = scan_metadata(cs_obj['MOBSF_MD5'])
        cs_obj['SCAN_TYPE'] = rs_obj['SCAN_TYPE'] if rs_obj else None
        cs_obj['FILE_NAME'] = rs_obj['FILE_NAME'] if rs_obj else None
        return cs_obj
    return None


def new_cyberspect_scan(scheduled, md5, start_time,
                        file_size, source_file_size, sso_user):
    # Insert new record into CyberspectScans
    new_db_obj = CyberspectScans(
        SCHEDULED=scheduled,
        MOBSF_MD5=md5,
        INTAKE_START=start_time,
        FILE_SIZE_PACKAGE=file_size,
        FILE_SIZE_SOURCE=source_file_size,
        EMAIL=sso_user,
    )
    new_db_obj.save()
    logger.info('Hash: %s, Cyberspect Scan ID: %s', md5, new_db_obj.ID)
    return new_db_obj.ID


def update_scan(request, api=False):
    """Update RecentScansDB record."""
    try:
        if (not is_admin(request) and not api):
            return HttpResponse(status=403)
        md5 = request.POST['hash']
        response = {'error': f'Scan {md5} not found'}
        db_obj = RecentScansDB.objects.filter(MD5=md5).first()
        if db_obj:
            if 'user_app_name' in request.POST:
                db_obj.USER_APP_NAME = request.POST['user_app_name']
            if 'user_app_version' in request.POST:
                db_obj.USER_APP_VERSION = request.POST['user_app_version']
            if 'division' in request.POST:
                db_obj.DIVISION = request.POST['division']
            if 'environment' in request.POST:
                db_obj.ENVIRONMENT = request.POST['environment']
            if 'country' in request.POST:
                db_obj.COUNTRY = request.POST['country']
            if 'data_privacy_classification' in request.POST:
                dpc = request.POST['data_privacy_classification']
                db_obj.DATA_PRIVACY_CLASSIFICATION = dpc
            if 'data_privacy_attributes' in request.POST:
                dpa = request.POST['data_privacy_attributes']
                db_obj.DATA_PRIVACY_ATTRIBUTES = dpa
            if 'email' in request.POST:
                db_obj.EMAIL = request.POST['email']
            if 'release' in request.POST:
                db_obj.RELEASE = request.POST['release']
            db_obj.TIMESTAMP = utcnow()
            db_obj.save()
            response = model_to_dict(db_obj)
            data = {'result': 'success'}
        if api:
            return response
        else:
            ctype = 'application/json; charset=utf-8'
            return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
        logger.error(exmsg)
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return error_response(request, msg, True, exp_doc)
        else:
            return error_response(request, msg, False, exp_doc)


def update_cyberspect_scan(data):
    """Update Cyberspect scan record."""
    try:
        if (('id' not in data) and ('dt_project_id' in data)):
            db_obj = CyberspectScans.objects \
                .filter(DT_PROJECT_ID=data['dt_project_id']) \
                .order_by('-ID').first()
            csid = data['dt_project_id']
        else:
            db_obj = CyberspectScans.objects.filter(ID=data['id']).first()
            csid = data['id']

        if db_obj:
            if 'mobsf_md5' in data:
                db_obj.MOBSF_MD5 = data['mobsf_md5']
            if 'dt_project_id' in data and data['dt_project_id']:
                db_obj.DT_PROJECT_ID = data['dt_project_id']
            if 'intake_end' in data and data['intake_end']:
                db_obj.INTAKE_END = tz(data['intake_end'])
            if 'sast_start' in data and data['sast_start']:
                db_obj.SAST_START = tz(data['sast_start'])
            if 'sast_end' in data and data['sast_end']:
                db_obj.SAST_END = tz(data['sast_end'])
            if 'sbom_start' in data and data['sbom_start']:
                db_obj.SBOM_START = tz(data['sbom_start'])
            if 'sbom_end' in data and data['sbom_end']:
                db_obj.SBOM_END = tz(data['sbom_end'])
            if 'dependency_start' in data and data['dependency_start']:
                db_obj.DEPENDENCY_START = tz(data['dependency_start'])
            if 'dependency_end' in data and data['dependency_end']:
                db_obj.DEPENDENCY_END = tz(data['dependency_end'])
            if 'notification_start' in data and data['notification_start']:
                db_obj.NOTIFICATION_START = tz(data['notification_start'])
            if 'notification_end' in data and data['notification_end']:
                db_obj.NOTIFICATION_END = tz(data['notification_end'])
            if 'success' in data:
                db_obj.SUCCESS = data['success']
            if 'failure_source' in data and data['failure_source']:
                db_obj.FAILURE_SOURCE = data['failure_source']
            if 'failure_message' in data and data['failure_message']:
                db_obj.FAILURE_MESSAGE = data['failure_message']
            if 'file_size_package' in data and data['file_size_package']:
                db_obj.FILE_SIZE_PACKAGE = data['file_size_package']
            if 'file_size_source' in data and data['file_size_source']:
                db_obj.FILE_SIZE_SOURCE = data['file_size_source']
            if 'dependency_types' in data:
                db_obj.DEPENDENCY_TYPES = data['dependency_types']
            db_obj.save()
            return model_to_dict(db_obj)
        else:
            return {'error': f'Scan ID {csid} not found'}
    except Exception as ex:
        exmsg = ''.join(tb.format_exception(None, ex, ex.__traceback__))
        logger.error(exmsg)
        return {'error': str(ex)}


def logout_aws(request):
    """Remove AWS ALB session cookie."""
    resp = HttpResponse(
        '{}',
        content_type='application/json; charset=utf-8')
    for cookie in request.COOKIES:
        resp.set_cookie(cookie, None, -1, -1)
    return resp


def download_apk(request):
    """Download and APK by package name."""
    package = request.POST['package']
    # Package validated in apk_download()
    context = {
        'status': 'failed',
        'description': 'Unable to download APK',
    }
    res = apk_download(package)
    if res:
        context = res
        context['status'] = 'ok'
        context['package'] = package
    resp = HttpResponse(
        json.dumps(context),
        content_type='application/json; charset=utf-8')
    return resp


def search(request):
    """Search Scan by MD5 Route."""
    md5 = request.GET['md5']
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if db_obj.exists():
            e = db_obj[0]
            url = (f'/{e.ANALYZER }/?file_name={e.FILE_NAME}&'
                   f'hash={e.MD5}&scan_type={e.SCAN_TYPE}')
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/not_found/')
    return error_response(request,
                          'The Scan ID provided is invalid. Please provide a'
                          + ' valid 32 character alphanumeric value.')


@require_http_methods(['GET'])
def app_info(request):
    """Get mobile app info by user supplied name."""
    appname = request.GET['name']
    db_obj = RecentScansDB.objects \
        .filter(Q(APP_NAME__icontains=appname)
                | Q(USER_APP_NAME__icontains=appname)) \
        .order_by('-TIMESTAMP')
    user = sso_email(request)
    if db_obj.exists():
        e = db_obj[0]
        if user == e.EMAIL or is_admin(request):
            context = {
                'found': True,
                'version': e.USER_APP_VERSION,
                'division': e.DIVISION,
                'country': e.COUNTRY,
                'environment': e.ENVIRONMENT,
                'data_privacy_classification': e.DATA_PRIVACY_CLASSIFICATION,
                'data_privacy_attributes': e.DATA_PRIVACY_ATTRIBUTES,
                'release': e.RELEASE,
                'email': e.EMAIL,
            }
            logger.info('Found existing mobile app information for %s',
                        appname)
            return HttpResponse(json.dumps(context),
                                content_type='application/json', status=200)
        else:
            logger.info('User is not authorized for %s.', appname)
            payload = {'found': False}
            return HttpResponse(json.dumps(payload),
                                content_type='application/json', status=200)
    else:
        logger.info('Unable to find mobile app information for %s',
                    appname)
        payload = {'found': False}
        return HttpResponse(json.dumps(payload),
                            content_type='application/json', status=200)


def download(request):
    """Download from mobsf.MobSF Route."""
    if request.method == 'GET':
        root = settings.DWD_DIR
        allowed_exts = settings.ALLOWED_EXTENSIONS
        filename = request.path.replace('/download/', '', 1)
        dwd_file = os.path.join(root, filename)
        # Security Checks
        if '../' in filename or not is_safe_path(root, dwd_file):
            msg = 'Path Traversal Attack Detected'
            return error_response(request, msg)
        ext = os.path.splitext(filename)[1]
        if ext in allowed_exts:
            if os.path.isfile(dwd_file):
                wrapper = FileWrapper(
                    open(dwd_file, 'rb'))  # lgtm [py/path-injection]
                response = HttpResponse(
                    wrapper, content_type=allowed_exts[ext])
                response['Content-Length'] = os.path.getsize(dwd_file)
                return response
        if filename.endswith(('screen/screen.png', '-icon.png')):
            return HttpResponse('')
    return HttpResponse(status=404)


def generate_download(request, api=False):
    """Generate downloads for uploaded binaries/source."""
    try:
        binary = ('apk', 'ipa', 'jar', 'aar', 'so', 'dylib', 'a')
        source = ('smali', 'java')
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        match = re.match('^[0-9a-f]{32}$', md5)
        if (not match
                or file_type not in binary + source):
            msg = 'Invalid download type or hash'
            logger.exception(msg)
            return error_response(request, msg)
        app_dir = Path(settings.UPLD_DIR) / md5
        dwd_dir = Path(settings.DWD_DIR)
        file_name = ''
        if file_type == 'java':
            # For Java zipped source code
            directory = app_dir / 'java_source'
            dwd_file = dwd_dir / f'{md5}-java'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-java.zip'
        elif file_type == 'smali':
            # For Smali zipped source code
            directory = app_dir / 'smali_source'
            dwd_file = dwd_dir / f'{md5}-smali'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-smali.zip'
        elif file_type in binary:
            # Binaries
            src_file_name = f'{md5}.{file_type}'
            src = app_dir / src_file_name
            file_name = dwd_dir / src_file_name
            shutil.copy2(src.as_posix(), file_name.as_posix())
        if not api:
            return redirect(f'/download/{file_name}')
        else:
            return {'file_name': file_name}
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return error_response(request, msg)


def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if request.method == 'POST':
            if api:
                md5_hash = request.POST['hash']
            else:
                md5_hash = request.POST['md5']
            data = {'deleted': 'scan hash not found'}
            if re.match('[0-9a-f]{32}', md5_hash):
                # Delete DB Entries
                scan = RecentScansDB.objects.filter(MD5=md5_hash)
                if scan.exists():
                    RecentScansDB.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerIOS.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
                    # Delete Upload Dir Contents
                    app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
                    if is_dir_exists(app_upload_dir):
                        shutil.rmtree(app_upload_dir)
                    # Delete Download Dir Contents
                    dw_dir = settings.DWD_DIR
                    for item in os.listdir(dw_dir):
                        item_path = os.path.join(dw_dir, item)
                        valid_item = item.startswith(md5_hash + '-')
                        # Delete all related files
                        if is_file_exists(item_path) and valid_item:
                            os.remove(item_path)
                        # Delete related directories
                        if is_dir_exists(item_path) and valid_item:
                            shutil.rmtree(item_path)
                    data = {'deleted': 'yes'}
            if api:
                return data
            else:
                ctype = 'application/json; charset=utf-8'
                return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return error_response(request, msg, True, exp_doc)
        else:
            return error_response(request, msg, False, exp_doc)


def cyberspect_rescan(apphash, scheduled, sso_user):
    """Get cyberspect scan by hash."""
    rs_obj = RecentScansDB.objects.filter(MD5=apphash).first()
    if not rs_obj:
        return None
    # Get file sizes
    file_path = os.path.join(settings.UPLD_DIR, apphash + '/') \
        + apphash + '.' + rs_obj.SCAN_TYPE
    file_size = os.path.getsize(file_path)
    source_file_size = 0
    if os.path.exists(file_path + '.src'):
        source_file_size = os.path.getsize(file_path + '.src')

    start_time = utcnow()
    scan_id = new_cyberspect_scan(scheduled, apphash, start_time,
                                  file_size, source_file_size, sso_user)
    scan_data = {
        'cyberspect_scan_id': scan_id,
        'hash': apphash,
        'short_hash': get_siphash(apphash),
        'scan_type': rs_obj.SCAN_TYPE,
        'file_name': rs_obj.FILE_NAME,
        'user_app_name': rs_obj.USER_APP_NAME,
        'user_app_version': rs_obj.USER_APP_VERSION,
        'email': rs_obj.EMAIL,
        'rescan': '1',
    }
    cyberspect_scan_intake(scan_data)
    return scan_data


def cyberspect_scan_intake(scan):
    if not settings.AWS_INTAKE_LAMBDA:
        logging.warning('Environment variable AWS_INTAKE_LAMBDA not set')
        return

    lclient = boto3.client('lambda')
    file_path = os.path.join(settings.UPLD_DIR, scan['hash'] + '/') \
        + scan['hash'] + '.' + scan['scan_type']
    if (os.path.exists(file_path + '.src')):
        file_path = file_path + '.src'
    lambda_params = {
        'cyberspect_scan_id': scan['cyberspect_scan_id'],
        'hash': scan['hash'],
        'short_hash': scan['short_hash'],
        'user_app_name': scan['user_app_name'],
        'user_app_version': scan['user_app_version'],
        'scan_type': scan['scan_type'],
        'email': scan['email'],
        'file_name': file_path,
        'rescan': scan['rescan'],
    }
    logger.info('Executing Cyberspect intake lambda: %s',
                settings.AWS_INTAKE_LAMBDA)
    lclient.invoke(FunctionName=settings.AWS_INTAKE_LAMBDA,
                   InvocationType='Event',
                   Payload=json.dumps(lambda_params).encode('utf-8'))
    return


def health(request):
    """Check MobSF system health."""
    # Ensure database access is good
    RecentScansDB.objects.all().first()
    data = {'status': 'OK'}
    return HttpResponse(json.dumps(data),
                        content_type='application/json; charset=utf-8')


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def cyberspect_recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        cs_scans = CyberspectScans.objects.all()
        result = cs_scans.values().order_by('-INTAKE_START')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }

        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def cyberspect_completed_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        def_date = datetime.datetime.now(datetime.timezone.utc) \
            - datetime.timedelta(hours=24)
        from_date = tz(self.request.GET.get('from_date', def_date))
        result = CyberspectScans.objects.filter(SCHEDULED=True,
                                                INTAKE_START__gte=from_date) \
            .values().order_by('ID')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                for scan in content:
                    # Get app details
                    md5 = scan['MOBSF_MD5']
                    scan_result = RecentScansDB.objects.filter(MD5=md5) \
                        .first()
                    if scan_result:
                        scan['APP_NAME'] = scan_result.APP_NAME
                        scan['VERSION_NAME'] = scan_result.VERSION_NAME
                        scan['PACKAGE_NAME'] = scan_result.PACKAGE_NAME
                        scan['SCAN_TYPE'] = scan_result.SCAN_TYPE
                        scan['DATA_PRIVACY_CLASSIFICATION'] = \
                            scan_result.DATA_PRIVACY_CLASSIFICATION
                        scan['EMAIL'] = scan_result.EMAIL

                        # Get scan vulnerability counts
                        findings = appsec.appsec_dashboard(self.request, md5,
                                                           True)
                        scan['FINDINGS_HIGH'] = len(findings['high']) \
                            if 'high' in findings else 0
                        scan['FINDINGS_WARNING'] = len(findings['warning']) \
                            if 'warning' in findings else 0
                        scan['FINDINGS_INFO'] = len(findings['info']) \
                            if 'info' in findings else 0
                        scan['SECURITY_SCORE'] = findings['security_score']
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data

    def release_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        scans = RecentScansDB.objects.filter(RELEASE=True)
        result = scans.values().order_by('APP_NAME', 'VERSION_NAME')
        try:
            paginator = Paginator(result, page_size)
            if (int(page) > paginator.num_pages):
                data = {
                    'content': [],
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
            else:
                content = paginator.page(page)
                data = {
                    'content': list(content),
                    'count': paginator.count,
                    'num_pages': paginator.num_pages,
                }
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            data = {'error': str(exp)}
        return data
