# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
import re
import os
import time
from pathlib import Path



from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render
from django.core.signing import Signer

from mobsf.MobSF.utils import (
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS

from mobsf.DynamicAnalyzer.views.ios.utils import (
    common_check,
    SALT,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumAPI,
    CorelliumInstanceAPI,
)

logger = logging.getLogger(__name__)


def dynamic_analysis(request, api=False):
    """iOS Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        ios_dynamic = False
        ipas = StaticAnalyzerIOS.objects.filter(
            FILE_NAME__endswith='.ipa')
        for ipa in reversed(ipas):
            temp_dict = {
                'MD5': ipa.MD5,
                'APP_NAME': ipa.APP_NAME,
                'APP_VERSION': ipa.APP_VERSION,
                'FILE_NAME': ipa.FILE_NAME,
                'BUNDLE_ID': ipa.BUNDLE_ID,
                'DYNAMIC_REPORT_EXISTS': False,
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
        if c.api_ready() and c.get_projects():
            instances = c.get_instances()
            project_id = c.project_id
        context = {'apps': scan_apps,
                   'dynamic_analyzer': ios_dynamic,
                   'project_id': project_id,
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


def dynamic_analyzer(request, checksum, api=False):
    """iOS Dynamic Analyzer."""
    try:
        instance_id =  request.GET.get('instance_id')
       
        failed = common_check(instance_id)
        if failed:
            return print_n_send_error_response(
                request,
                failed['message'],
                api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
        signer = Signer(salt=SALT)
        ssh = signer.sign_object(ci.get_ssh_connection_string())
        db_entry = StaticAnalyzerIOS.objects.filter(
                    MD5=checksum)
        context = {
            'hash': checksum,
            'instance_id': instance_id,
            'bundle_id': db_entry[0].BUNDLE_ID,
            'version': settings.MOBSF_VER,
            'ssh_signed': ssh,
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