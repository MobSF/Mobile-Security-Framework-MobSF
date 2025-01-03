# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.ios.analysis import (
    get_screenshots,
    ios_api_analysis,
    run_analysis,
)
from mobsf.MobSF.utils import (
    base64_decode,
    common_check,
    get_md5,
    key,
    pretty_json,
    print_n_send_error_response,
    replace,
    strict_package_check,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)


logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('replace', replace)
register.filter('pretty_json', pretty_json)
register.filter('base64_decode', base64_decode)


@login_required
def ios_view_report(request, bundle_id, api=False):
    """Dynamic Analysis Report Generation."""
    logger.info('iOS Dynamic Analysis Report Generation')
    try:
        if api:
            instance_id = request.POST.get('instance_id')
        else:
            instance_id = request.GET.get('instance_id')
        if instance_id and not common_check(instance_id):
            dev = instance_id
        else:
            dev = ''
        if not strict_package_check(bundle_id):
            # We need this check since bundleid
            # is not validated in REST API
            return print_n_send_error_response(
                request,
                'Invalid iOS Bundle id',
                api)
        checksum = get_md5(bundle_id.encode('utf-8'))
        app_dir = Path(settings.UPLD_DIR) / checksum
        download_dir = settings.DWD_DIR
        tools_dir = settings.TOOLS_DIR
        frida_log = app_dir / 'mobsf_frida_out.txt'
        if not frida_log.exists():
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg, api)
        api_analysis = ios_api_analysis(app_dir)
        dump_analaysis = run_analysis(app_dir, bundle_id, checksum)
        trk = Trackers.Trackers(checksum, app_dir, tools_dir)
        trackers = trk.get_trackers_domains_or_deps(
            dump_analaysis['domains'], None)
        screenshots = get_screenshots(checksum, download_dir)
        context = {
            'hash': checksum,
            'version': settings.MOBSF_VER,
            'title': 'iOS Dynamic Analysis Report',
            'instance_id': dev,
            'bundleid': bundle_id,
            'trackers': trackers,
            'screenshots': screenshots,
            'frida_logs': frida_log.exists(),
        }
        context.update(api_analysis)
        context.update(dump_analaysis)
        template = 'dynamic_analysis/ios/dynamic_report.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = f'Error Generating Dynamic Analysis Report. {str(exp)}'
        return print_n_send_error_response(request, err, api)
