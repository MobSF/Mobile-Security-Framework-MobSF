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
from datetime import timedelta
from wsgiref.util import FileWrapper

from django.conf import settings
from django.utils.timezone import now
from django.core.paginator import Paginator
from django.db.models import Q
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
from mobsf.MobSF.security import sanitize_filename, sanitize_svg
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
# Cyberspect imports
from mobsf.StaticAnalyzer.views.common import appsec
from mobsf.StaticAnalyzer.cyberspect_models import (
    CyberspectScans,
)

from cyberspect.MobSF.views.home import (
    cyberspect_scan_intake,
    new_cyberspect_scan,
    track_failure,
)
from cyberspect.utils import (
    get_siphash,
    is_admin,
    sso_email,
    tz,
    utcnow,
)
# Cyberspect imports end


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
        'title': 'Cyberspect: Upload App',
        'mimes': mimes,
        'exts': '|'.join(exts),
        'email': sso_email(request),  # Cyberspect mod
        'tenant_static': settings.TENANT_STATIC_URL,  # Cyberspect mod
    }
    template = 'general/home2.html'
    return render(request, template, context)


class Upload(object):
    """Handle File Upload based on App type."""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_type = None
        self.file = None
        self.email = sso_email(request)  # Cyberspect mod

    @staticmethod
    @login_required
    @permission_required(Permissions.SCAN)
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
            msg = 'File format not supported: ' \
                + self.file.content_type
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
        logger.info('Uploading through API')
        api_response = {}
        request = self.request
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            api_response['error'] = 'File format not supported!'
            return api_response, HTTP_BAD_REQUEST
        # Cyberspect mods begin
        if not self.email:
            api_response['error'] = 'User email address not set'
            return api_response, HTTP_BAD_REQUEST
        # Cyberspect mods end
        api_response = self.upload()
        return api_response, 200

    def upload(self):
        self.rescan = '0'
        request = self.request
        scanning = Scanning(request)
        content_type = self.file.content_type
        file_name = sanitize_filename(self.file.name)
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.file_type.is_apk():
            result = scanning.scan_apk()
        elif self.file_type.is_xapk():
            result = scanning.scan_xapk()
        elif self.file_type.is_apks():
            result = scanning.scan_apks()
        elif self.file_type.is_aab():
            result = scanning.scan_aab()
        elif self.file_type.is_jar():
            result = scanning.scan_jar()
        elif self.file_type.is_aar():
            result = scanning.scan_aar()
        elif self.file_type.is_so():
            result = scanning.scan_so()
        elif self.file_type.is_zip():
            result = scanning.scan_zip()
        elif self.file_type.is_ipa():
            result = scanning.scan_ipa()
        elif self.file_type.is_dylib():
            result = scanning.scan_dylib()
        elif self.file_type.is_a():
            result = scanning.scan_a()
        elif self.file_type.is_appx():
            result = scanning.scan_appx()

        # Cyberspect mods begin
        try:
            self.cyberspect_scan_id = new_cyberspect_scan(
                scheduled=False,
                apphash=result['hash'],
                start_time=utcnow(),
                email=self.email,
            )
            if 'short_hash' not in result:
                result['short_hash'] = get_siphash(result['hash'])
            if 'cyberspect_scan_id' not in result:
                result['cyberspect_scan_id'] = self.cyberspect_scan_id
            cyberspect_scan_intake(result, self.cyberspect_scan_id)
        except Exception as exp:
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            msg = str(exp)
            exp_doc = exp.__doc__
            track_failure(msg, self.cyberspect_scan_id)
            return print_n_send_error_response(request, msg, True, exp_doc)

        # Cyberspect mods end

        return result


@login_required
def api_docs(request):
    """Api Docs Route."""
    if (not is_admin(request)):  # Cyberspect mod
        return print_n_send_error_response(request, 'Unauthorized')  # Cyberspect mod

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
        'is_admin': True,
    }
    template = 'general/apidocs.html'
    return render(request, template, context)


def about(request):
    """About Route."""
    context = {
        'title': 'About',
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
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
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
def recent_scans(request, page_size=20, page_number=1):
    """Show Recent Scans Route."""
    entries = []
    # Cyberspect mods begin
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

    user_email = sso_email(request)
    isadmin = is_admin(request)
    if (not isadmin):
        if (not user_email):
            user_email = '@@'
        db_obj = db_obj.filter(EMAIL__contains=user_email)
    db_obj = db_obj.order_by('-TIMESTAMP').values()

    paginator = Paginator(db_obj, page_size)
    # Cyberspect mods end
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
        # Cyberspect mods begin
        entry['CAN_RELEASE'] = (utcnow()
                                < entry['TIMESTAMP']
                                + datetime.timedelta(days=30))
        # Check if user owns this scan
        entry['USER_OWNS_SCAN'] = (
            isadmin or (
                user_email
                and entry['EMAIL']
                and (
                    user_email.lower() == entry['EMAIL'].lower()
                    or user_email.lower()
                    in [e.strip().lower() for e in entry['EMAIL'].split(',')]
                )
            )
        )
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
        # Cyberspect mods end
        entries.append(entry)

    paginator_range = page_obj.paginator.get_elided_page_range(
        page_number,
        on_each_side=3,
        on_ends=1,
    )
    context = {
        'title': 'Scanned Apps',
        'entries': entries,
        'version': settings.MOBSF_VER,
        'page_obj': page_obj,
        # Cyberspect mods begin
        'dependency_track_url': settings.DEPENDENCY_TRACK_URL,
        'filter': filter,
        'tenant_static': settings.TENANT_STATIC_URL,
        'paginator_range': paginator_range,
        # Cyberspect mods end
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
    def create_response(content, is_binary=True):
        """Helper function to create HTTP response."""
        if is_binary:
            wrapper = FileWrapper(content)
            response = HttpResponse(wrapper, content_type=content_type)
            response['Content-Length'] = dwd_file.stat().st_size
        else:
            response = HttpResponse(content, content_type=content_type)
        if filename:
            # Remove CRLF from filename to prevent header injection
            safe_filename = filename.replace('\r', '').replace('\n', '')
            val = f'attachment; filename="{safe_filename}"'
            response['Content-Disposition'] = val
        return response

    # Handle SVG files with bleach cleaning to prevent XSS attacks
    if dwd_file.suffix == '.svg':
        with open(dwd_file, 'r', encoding='utf-8') as file:
            svg_content = file.read()
            cleaned_svg = sanitize_svg(svg_content)
            return create_response(cleaned_svg, is_binary=False)

    # Handle all other binary file types
    with open(dwd_file, 'rb') as file:
        return create_response(file)


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
    if not is_safe_path(root, dwd_file, filename):
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
def generate_download(request, api=False):
    """Generate downloads for uploaded binaries/source."""
    try:
        # Cyberspect add begins
        exts = ('apk', 'ipa', 'jar', 'aar', 'so', 'dylib', 'a',
                'zip', 'apk.src', 'ipa.src')
        source = ('smali', 'java')
        logger.info('Generating Downloads')
        # Cyberspect add ends
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        # Cyberspect add begins
        match = re.match('^[0-9a-f]{32}$', md5)
        if (not match
                or file_type not in exts + source):
            msg = 'Invalid download type or hash'
            logger.exception(msg)
            return print_n_send_error_response(request, msg)
        # Cyberspect add ends
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
        # Cyberspect add begins
        elif file_type == 'binary':
            # Binaries
            file_name = f'{md5}.{file_type}'
            src = app_dir / file_name
            dst = dwd_dir / file_name
            shutil.copy2(src.as_posix(), dst.as_posix())
        else:
            src_file_name = f'{md5}.{file_type}'
            src = app_dir / src_file_name
            file_name = dwd_dir / src_file_name
            shutil.copy2(src.as_posix(), file_name.as_posix())
        if not api:
            return redirect(f'/download/{file_name}')
        else:
            return {'file_name': file_name}
        # Cyberspect add ends
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
        # Cyberspect mods begin
        # Add check for async worker to prevent nested async
        in_async_worker = request.META.get('_in_async_worker', False)
        if settings.ASYNC_ANALYSIS and not in_async_worker:
            # Cyberspect mods end
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
        # Cyberspect mods begin
        try:
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
        except OSError as e:
            excmsg = str(e)
            msg = f'Failed to delete scan files: {excmsg} - '
            f'{app_upload_dir} - {dw_dir} - {item_path} - {valid_item} - {item}'
            logger.error(msg)
        # Cyberspect mods end
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
            # Cyberspect mods begin
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
            # Cyberspect mods end
        except Exception as exp:
            # Cyberspect mods begin
            exmsg = ''.join(tb.format_exception(None, exp, exp.__traceback__))
            logger.error(exmsg)
            # Cyberspect mods end
            data = {'error': str(exp)}
        return data

    # Cyberspect adds begin
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
        scans = RecentScansDB.objects.filter(RELEASE=True) \
            .exclude(ENVIRONMENT='Decommissioned')
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
    # Cyberspect adds end


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)
