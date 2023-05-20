"""Handle JAR and AAR files."""
import logging

from django.conf import settings
from django.shortcuts import render

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MobSF.utils import (
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    get_avg_cvss,
    hash_gen,
    unzip,
    update_scan_timestamp,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    get_manifest,
    manifest_analysis,
    manifest_data,
)
from mobsf.StaticAnalyzer.views.android.strings import strings_from_apk
from mobsf.StaticAnalyzer.views.android.binary_analysis import elf_analysis
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
)
from mobsf.StaticAnalyzer.views.android.code_analysis import code_analysis
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

logger = logging.getLogger(__name__)


def common_analysis(request, app_dic, rescan, api, analysis_type):
    app_dic['app_file'] = f'{app_dic["md5"]}.{analysis_type}'  # NEW FILENAME
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5'])
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
    else:
        app_dic['size'] = f'{str(file_size(app_dic["app_path"]))}MB'
        app_dic['sha1'], app_dic['sha256'] = hash_gen(app_dic['app_path'])
        app_dic['files'] = unzip(app_dic['app_path'], app_dic['app_dir'])
        logger.info('%s Extracted', analysis_type.upper())
        if not app_dic['files']:
            return print_n_send_error_response(
                request,
                f'{analysis_type.upper()} file is invalid or corrupt',
                api)
        app_dic['certz'] = get_hardcoded_cert_keystore(app_dic['files'])
        app_dic['playstore'] = {'error': True}
        if analysis_type == 'aar':
            # AAR has manifest and sometimes certificate
            app_dic['manifest_file'], app_dic['parsed_xml'] = get_manifest(
                app_dic['app_path'],
                app_dic['app_dir'],
                app_dic['tools_dir'],
                'aar',
            )
            app_dic['mani'] = (
                f'../manifest_view/?md5={app_dic["md5"]}&type=aar')
            man_data_dic = manifest_data(app_dic['parsed_xml'])
            man_an_dic = manifest_analysis(
                app_dic['parsed_xml'],
                man_data_dic,
                '',
                app_dic['app_dir'],
            )
            cert_dic = cert_info(
                app_dic['app_dir'],
                app_dic['app_file'],
                man_data_dic)
        else:
            app_dic['manifest_file'] = None
            app_dic['parsed_xml'] = ''
            app_dic['mani'] = ''
            man_data_dic = {
                'services': [],
                'activities': [],
                'receivers': [],
                'providers': [],
                'libraries': [],
                'categories': [],
                'perm': {},
                'packagename': app_dic['app_name'],
                'mainactivity': '',
                'min_sdk': '',
                'max_sdk': '',
                'target_sdk': '',
                'androver': '',
                'androvername': '',
                'icons': [],
            }
            man_an_dic = {
                'manifest_anal': [],
                'exported_act': [],
                'exported_cnt': {
                    'exported_activities': 0,
                    'exported_services': 0,
                    'exported_receivers': 0,
                    'exported_providers': 0,
                },
                'browsable_activities': {},
                'permissions': {},
                'icon_hidden': True,
                'network_security': {
                    'network_findings': [],
                    'network_summary': {},
                },
            }
            cert_dic = {
                'certificate_info': '',
                'certificate_findings': [],
                'certificate_summary': {},
            }
        app_dic['real_name'] = ''
        elf_dict = elf_analysis(app_dic['app_dir'])
        apkid_results = {}
        tracker = Trackers.Trackers(
            app_dic['app_dir'],
            app_dic['tools_dir'])
        tracker_res = tracker.get_trackers()

        apk_2_java(
            app_dic['app_path'],
            app_dic['app_dir'],
            app_dic['tools_dir'])

        code_an_dic = code_analysis(
            app_dic['app_dir'],
            'apk',
            app_dic['manifest_file'])

        quark_results = []

        # Get the strings from android resource and shared objects
        string_res = strings_from_apk(
            app_dic['app_file'],
            app_dic['app_dir'],
            elf_dict['elf_strings'])
        if string_res:
            app_dic['strings'] = string_res['strings']
            app_dic['secrets'] = string_res['secrets']
            code_an_dic['urls_list'].extend(
                string_res['urls_list'])
            code_an_dic['urls'].extend(string_res['url_nf'])
            code_an_dic['emails'].extend(string_res['emails_nf'])
        else:
            app_dic['strings'] = []
            app_dic['secrets'] = []
        # Firebase DB Check
        code_an_dic['firebase'] = firebase_analysis(
            list(set(code_an_dic['urls_list'])))
        # Domain Extraction and Malware Check
        logger.info(
            'Performing Malware Check on extracted Domains')
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            list(set(code_an_dic['urls_list'])))
        app_dic['zipped'] = analysis_type
        app_dic['icon_hidden'] = True
        app_dic['icon_found'] = False
        logger.info('Connecting to Database')
        try:
            # SAVE TO DB
            if rescan:
                logger.info('Updating Database...')
                save_or_update(
                    'update',
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                    elf_dict['elf_analysis'],
                    apkid_results,
                    quark_results,
                    tracker_res,
                )
                update_scan_timestamp(app_dic['md5'])
            else:
                logger.info('Saving to Database')
                save_or_update(
                    'save',
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                    elf_dict['elf_analysis'],
                    apkid_results,
                    quark_results,
                    tracker_res,
                )
        except Exception:
            logger.exception('Saving to Database Failed')
        context = get_context_from_analysis(
            app_dic,
            man_data_dic,
            man_an_dic,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            quark_results,
            tracker_res,
        )
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(
        context['code_analysis'])
    context['dynamic_analysis_done'] = False
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal()
        context['virus_total'] = vt.get_result(
            app_dic['app_path'],
            app_dic['md5'])
    template = 'static_analysis/android_binary_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)


def jar_analysis(request, app_dic, rescan, api):
    return common_analysis(request, app_dic, rescan, api, 'jar')


def aar_analysis(request, app_dic, rescan, api):
    return common_analysis(request, app_dic, rescan, api, 'aar')
