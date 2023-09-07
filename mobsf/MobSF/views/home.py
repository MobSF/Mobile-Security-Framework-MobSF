# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import json
import logging
import os
import platform
import re
import shutil
from pathlib import Path
from wsgiref.util import FileWrapper

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone
from django.shortcuts import (
    redirect,
    render,
)
from django.template.defaulttags import register

from mobsf.MobSF.forms import FormUtil, UploadFileForm
from mobsf.MobSF.utils import (
    api_key,
    is_dir_exists,
    is_file_exists,
    is_safe_path,
    key,
    print_n_send_error_response,
)
from mobsf.MobSF.views.helpers import FileType
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)

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
        'version': settings.MOBSF_VER,
        'mimes': mimes,
    }
    template = 'general/home.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_type = None
        self.file = None

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    def upload_html(self):
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

        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            msg = 'File format not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if self.file_type.is_ipa():
            if platform.system() not in LINUX_PLATFORM:
                msg = 'Static Analysis of iOS IPA requires Mac or Linux'
                logger.error(msg)
                response_data['description'] = msg
                return self.resp_json(response_data)

        response_data = self.upload()
        return self.resp_json(response_data)

    def upload_api(self):
        """API File Upload."""
        api_response = {}
        request = self.request
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            api_response['error'] = 'File format not Supported!'
            return api_response, HTTP_BAD_REQUEST
        api_response = self.upload()
        return api_response, 200

    def upload(self):
        request = self.request
        scanning = Scanning(request)
        content_type = self.file.content_type
        file_name = self.file.name
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.file_type.is_apk():
            return scanning.scan_apk()
        elif self.file_type.is_xapk():
            return scanning.scan_xapk()
        elif self.file_type.is_apks():
            return scanning.scan_apks()
        elif self.file_type.is_jar():
            return scanning.scan_jar()
        elif self.file_type.is_aar():
            return scanning.scan_aar()
        elif self.file_type.is_so():
            return scanning.scan_so()
        elif self.file_type.is_zip():
            return scanning.scan_zip()
        elif self.file_type.is_ipa():
            return scanning.scan_ipa()
        elif self.file_type.is_dylib():
            return scanning.scan_dylib()
        elif self.file_type.is_a():
            return scanning.scan_a()
        elif self.file_type.is_appx():
            return scanning.scan_appx()


def api_docs(request):
    """Api Docs Route."""
    context = {
        'title': 'REST API Docs',
        'api_key': api_key(),
        'version': settings.MOBSF_VER,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
        'version': settings.MOBSF_VER,
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
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
        'version': settings.MOBSF_VER,
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
    db_obj = RecentScansDB.objects.all().order_by('-TIMESTAMP').values()
    android = StaticAnalyzerAndroid.objects.all()
    ios = StaticAnalyzerIOS.objects.all()
    icon_mapping = {}
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
        icon_mapping[item.MD5] = item.ICON_PATH
    for item in ios:
        icon_mapping[item.MD5] = item.ICON_PATH
    for entry in db_obj:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        entry['ICON_PATH'] = icon_mapping.get(entry['MD5'], '')
        logcat = Path(settings.UPLD_DIR) / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = logcat.exists()
        entries.append(entry)
    context = {
        'title': 'Recent Scans',
        'entries': entries,
        'version': settings.MOBSF_VER,
    }
    template = 'general/recent.html'
    return render(request, template, context)


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
            url = f'/{e.ANALYZER }/{e.MD5}/'
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/not_found/')
    return print_n_send_error_response(request, 'Invalid Scan Hash')


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
            return print_n_send_error_response(request, msg)
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


def generate_download(request):
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
            return print_n_send_error_response(request, msg)
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
            file_name = f'{md5}.{file_type}'
            src = app_dir / file_name
            dst = dwd_dir / file_name
            shutil.copy2(src.as_posix(), dst.as_posix())
        return redirect(f'/download/{file_name}')
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)


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
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)


class RecentScans(object):

    def __init__(self, request):
        self.request = request

    def recent_scans(self):
        page = self.request.GET.get('page', 1)
        page_size = self.request.GET.get('page_size', 10)
        result = RecentScansDB.objects.all().values().order_by('-TIMESTAMP')
        try:
            paginator = Paginator(result, page_size)
            content = paginator.page(page)
            data = {
                'content': list(content),
                'count': paginator.count,
                'num_pages': paginator.num_pages,
            }
        except Exception as exp:
            data = {'error': str(exp)}
        return data


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)
