# -*- coding: utf_8 -*-
"""MobSF File Upload and Home Routes."""
import json
import logging
import os
import platform
import re
import shutil
from pathlib import Path
from datetime import timedelta
from wsgiref.util import FileWrapper

from django.conf import settings
from django.utils.timezone import now
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.shortcuts import (
    redirect,
    render,
)
from django.template.defaulttags import register

from mobsf.MobSF.forms import FormUtil, UploadFileForm
from mobsf.MobSF.utils import (
    MD5_REGEX,
    get_md5,
    is_dir_exists,
    is_file_exists,
    is_md5,
    is_safe_path,
    key,
    print_n_send_error_response,
    python_dict,
)
from mobsf.MobSF.init import api_key
from mobsf.MobSF.security import sanitize_filename
from mobsf.MobSF.views.helpers import FileType
from mobsf.MobSF.views.scanning import Scanning
from mobsf.MobSF.views.apk_downloader import apk_download
from mobsf.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    MAINTAINER_GROUP,
    Permissions,
    permission_required,
)

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
HTTP_STATUS_404 = 404
HTTP_SERVER_ERROR = 500
logger = logging.getLogger(__name__)
register.filter('key', key)


@login_required
def index(request):
    """Index Route."""
    mimes = (settings.APK_MIME
             + settings.IPA_MIME
             + settings.ZIP_MIME
             + settings.APPX_MIME)
    exts = (settings.ANDROID_EXTS
            + settings.IOS_EXTS
            + settings.WINDOWS_EXTS)
    context = {
        'version': settings.MOBSF_VER,
        'mimes': mimes,
        'exts': '|'.join(exts),
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
    @login_required
    @permission_required(Permissions.SCAN)
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
        elif self.file_type.is_aab():
            return scanning.scan_aab()
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


@login_required
def api_docs(request):
    """Api Docs Route."""
    key = '*******'
    try:
        if (settings.DISABLE_AUTHENTICATION == '1'
                or request.user.is_staff
                or request.user.groups.filter(name=MAINTAINER_GROUP).exists()):
            key = api_key(settings.MOBSF_HOME)
    except Exception:
        logger.exception('[ERROR] Failed to get API key')
    context = {
        'title': 'API Docs',
        'api_key': key,
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


def robots_txt(request):
    content = 'User-agent: *\nDisallow: /*/\nAllow: /*\n'
    return HttpResponse(content, content_type='text/plain')


@login_required
def dynamic_analysis(request):
    """Dynamic Analysis Landing."""
    context = {
        'title': 'Dynamic Analysis',
        'version': settings.MOBSF_VER,
    }
    template = 'general/dynamic.html'
    return render(request, template, context)


@login_required
def recent_scans(request, page_size=10, page_number=1):
    """Show Recent Scans Route."""
    entries = []
    paginator = Paginator(
        RecentScansDB.objects.all().order_by('-TIMESTAMP').values(), page_size)
    page_obj = paginator.get_page(page_number)
    page_obj.page_size = page_size
    md5_list = [i['MD5'] for i in page_obj]

    android = StaticAnalyzerAndroid.objects.filter(
        MD5__in=md5_list).only(
            'PACKAGE_NAME', 'VERSION_NAME', 'FILE_NAME', 'MD5')
    ios = StaticAnalyzerIOS.objects.filter(
        MD5__in=md5_list).only('FILE_NAME', 'MD5')

    updir = Path(settings.UPLD_DIR)
    icon_mapping = {}
    package_mapping = {}
    for item in android:
        package_mapping[item.MD5] = item.PACKAGE_NAME
        icon_mapping[item.MD5] = item.ICON_PATH
    for item in ios:
        icon_mapping[item.MD5] = item.ICON_PATH

    for entry in page_obj:
        if entry['MD5'] in package_mapping.keys():
            entry['PACKAGE'] = package_mapping[entry['MD5']]
        else:
            entry['PACKAGE'] = ''
        entry['ICON_PATH'] = icon_mapping.get(entry['MD5'], '')

        if entry['FILE_NAME'].endswith('.ipa'):
            entry['BUNDLE_HASH'] = get_md5(
                entry['PACKAGE_NAME'].encode('utf-8'))
            report_file = updir / entry['BUNDLE_HASH'] / 'mobsf_dump_file.txt'
        else:
            report_file = updir / entry['MD5'] / 'logcat.txt'
        entry['DYNAMIC_REPORT_EXISTS'] = report_file.exists()
        entries.append(entry)
    context = {
        'title': 'Recent Scans',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'page_obj': page_obj,
        'async_scans': settings.ASYNC_ANALYSIS,
    }
    template = 'general/recent.html'
    return render(request, template, context)


@login_required
@permission_required(Permissions.SCAN)
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


@login_required
def search(request, api=False):
    """Search scan by checksum or text."""
    if request.method == 'POST':
        query = request.POST['query']
    else:
        query = request.GET['query']

    if not query:
        msg = 'No search query provided.'
        return print_n_send_error_response(request, msg, api)

    checksum = query if re.match(MD5_REGEX, query) else find_checksum(query)

    if checksum and re.match(MD5_REGEX, checksum):
        db_obj = RecentScansDB.objects.filter(MD5=checksum).first()
        if db_obj:
            url = f'/{db_obj.ANALYZER}/{db_obj.MD5}/'
            if api:
                return {'checksum': db_obj.MD5}
            else:
                return HttpResponseRedirect(url)

    msg = 'You can search by MD5, app name, package name, or file name.'
    return print_n_send_error_response(request, msg, api, 'Scan not found')


def find_checksum(query):
    """Get the first matching checksum from the database."""
    search_fields = ['FILE_NAME', 'PACKAGE_NAME', 'APP_NAME']

    for field in search_fields:
        result = RecentScansDB.objects.filter(
            **{f'{field}__icontains': query}).first()
        if result:
            return result.MD5

    return None

# AJAX


@login_required
@require_http_methods(['POST'])
def scan_status(request, api=False):
    """Get Current Status of a scan in progress."""
    try:
        scan_hash = request.POST['hash']
        if not is_md5(scan_hash):
            return invalid_params(api)
        robj = RecentScansDB.objects.filter(MD5=scan_hash)
        if not robj.exists():
            data = {'status': 'failed', 'error': 'scan hash not found'}
            return send_response(data, api)
        data = {'status': 'ok', 'logs': python_dict(robj[0].SCAN_LOGS)}
    except Exception as exp:
        logger.exception('Fetching Scan Status')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)


def file_download(dwd_file, filename, content_type):
    """HTTP file download response."""
    with open(dwd_file, 'rb') as file:
        wrapper = FileWrapper(file)
        response = HttpResponse(wrapper, content_type=content_type)
        response['Content-Length'] = dwd_file.stat().st_size
        if filename:
            val = f'attachment; filename="{filename}"'
            response['Content-Disposition'] = val
        return response


@login_required
@require_http_methods(['GET'])
def download_binary(request, checksum, api=False):
    """Download binary from uploads directory."""
    try:
        allowed_exts = settings.ALLOWED_EXTENSIONS
        if not is_md5(checksum):
            return HttpResponse(
                'Invalid MD5 Hash',
                status=HTTP_STATUS_404)
        robj = RecentScansDB.objects.filter(MD5=checksum).first()
        if not robj:
            return HttpResponse(
                'Scan hash not found',
                status=HTTP_STATUS_404)
        file_ext = f'.{robj.SCAN_TYPE}'
        if file_ext not in allowed_exts.keys():
            return HttpResponse(
                'Invalid Scan Type',
                status=HTTP_STATUS_404)
        filename = f'{checksum}{file_ext}'
        dwd_file = Path(settings.UPLD_DIR) / checksum / filename
        if not dwd_file.exists():
            return HttpResponse(
                'File not found',
                status=HTTP_STATUS_404)
        return file_download(
            dwd_file,
            sanitize_filename(robj.FILE_NAME),
            allowed_exts[file_ext])
    except Exception:
        logger.exception('Download Binary Failed')
        return HttpResponse(
            'Failed to download file due to an error',
            status=HTTP_SERVER_ERROR)


@login_required
@require_http_methods(['GET'])
def download(request):
    """Download from mobsf downloads directory."""
    root = settings.DWD_DIR
    filename = request.path.replace('/download/', '', 1)
    dwd_file = Path(root) / filename

    # Security Checks
    if '../' in filename or not is_safe_path(root, dwd_file):
        msg = 'Path Traversal Attack Detected'
        return print_n_send_error_response(request, msg)

    # File and Extension Check
    ext = dwd_file.suffix
    allowed_exts = settings.ALLOWED_EXTENSIONS
    if ext in allowed_exts and dwd_file.is_file():
        return file_download(
            dwd_file,
            None,
            allowed_exts[ext])

    # Special Case for Certain Image Files
    if filename.endswith(('screen/screen.png', '-icon.png')):
        return HttpResponse('')

    return HttpResponse(status=HTTP_STATUS_404)


@login_required
def generate_download(request):
    """Generate downloads for smali/java zip."""
    try:
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        if (not is_md5(md5)
                or file_type not in ('smali', 'java')):
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
        return redirect(f'/download/{file_name}')
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)


@login_required
@permission_required(Permissions.DELETE)
@require_http_methods(['POST'])
def delete_scan(request, api=False):
    """Delete Scan from DB and remove the scan related files."""
    try:
        if api:
            md5_hash = request.POST['hash']
        else:
            md5_hash = request.POST['md5']

        if not re.match(MD5_REGEX, md5_hash):
            return send_response({'deleted': 'Invalid scan hash'}, api)

        # Delete DB Entries
        scan = RecentScansDB.objects.filter(MD5=md5_hash)
        if not scan.exists():
            return send_response({'deleted': 'Scan not found in Database'}, api)
        if settings.ASYNC_ANALYSIS:
            # Handle Async Tasks
            et = EnqueuedTask.objects.filter(checksum=md5_hash).first()
            if et:
                max_time_passed = now() - et.created_at > timedelta(
                    minutes=settings.ASYNC_ANALYSIS_TIMEOUT)
                if not (et.completed_at or max_time_passed):
                    # Queue is in progress, cannot delete the task
                    return send_response(
                        {'deleted': 'A scan can only be deleted after it is completed'},
                        api)
        # Delete all related DB entries
        EnqueuedTask.objects.filter(checksum=md5_hash).all().delete()
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
                shutil.rmtree(item_path, ignore_errors=True)
        return send_response({'deleted': 'yes'}, api)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, api, exp_doc)


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
