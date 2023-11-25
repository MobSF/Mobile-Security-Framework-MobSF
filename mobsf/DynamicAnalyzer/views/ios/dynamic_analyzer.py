# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    get_md5,
    print_n_send_error_response,
    python_dict,
    strict_package_check,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.DynamicAnalyzer.views.ios.utils import (
    common_check,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumAPI,
)

logger = logging.getLogger(__name__)


def dynamic_analysis(request, api=False):
    """The iOS Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        ios_dynamic = False
        ipas = StaticAnalyzerIOS.objects.filter(
            FILE_NAME__endswith='.ipa')
        for ipa in reversed(ipas):
            bundle_hash = get_md5(ipa.BUNDLE_ID.encode('utf-8'))
            frida_dump = Path(
                settings.UPLD_DIR) / bundle_hash / 'mobsf_dump_file.txt'
            encrypted = python_dict(
                ipa.MACHO_ANALYSIS)['encrypted']['is_encrypted']
            temp_dict = {
                'MD5': ipa.MD5,
                'APP_NAME': ipa.APP_NAME,
                'APP_VERSION': ipa.APP_VERSION,
                'FILE_NAME': ipa.FILE_NAME,
                'BUNDLE_ID': ipa.BUNDLE_ID,
                'BUNDLE_HASH': bundle_hash,
                'ENCRYPTED': encrypted,
                'DYNAMIC_REPORT_EXISTS': frida_dump.exists(),
            }
            scan_apps.append(temp_dict)
        # Corellium
        instances = []
        project_id = None
        corellium_api_key = getattr(settings, 'CORELLIUM_API_KEY', '')
        corellium_project_id = getattr(settings, 'CORELLIUM_PROJECT_ID', '')
        if corellium_api_key:
            ios_dynamic = True
        c = CorelliumAPI(corellium_api_key, corellium_project_id)
        if c.api_ready() and c.api_auth() and c.get_projects():
            instances = c.get_instances()
            project_id = c.project_id
        context = {'apps': scan_apps,
                   'dynamic_analyzer': ios_dynamic,
                   'project_id': project_id,
                   'corellium_auth': c.api_auth(),
                   'instances': instances,
                   'title': 'MobSF Dynamic Analysis',
                   'version': settings.MOBSF_VER}
        if api:
            return context
        template = 'dynamic_analysis/ios/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('iOS Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)


def dynamic_analyzer(request, api=False):
    """Dynamic Analyzer for in-device iOS apps."""
    try:
        bundleid = request.GET.get('bundleid')
        if not bundleid or not strict_package_check(bundleid):
            return print_n_send_error_response(
                request,
                'Invalid iOS Bundle id',
                api)
        instance_id = request.GET.get('instance_id')
        failed = common_check(instance_id)
        if failed:
            return print_n_send_error_response(
                request,
                failed['message'],
                api)
        bundle_hash = get_md5(bundleid.encode('utf-8'))
        app_dir = Path(settings.UPLD_DIR) / bundle_hash
        if not app_dir.exists():
            app_dir.mkdir()
        context = {
            'hash': bundle_hash,
            'instance_id': instance_id,
            'bundle_id': bundleid,
            'version': settings.MOBSF_VER,
            'title': 'iOS Dynamic Analyzer'}
        template = 'dynamic_analysis/ios/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('iOS Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'iOS Dynamic Analysis Failed.',
            api)
