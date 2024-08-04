"""Handle (.so) Shared Object file."""
import logging

from django.conf import settings
from django.shortcuts import render

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    get_symbols,
    hash_gen,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)


def so_analysis(request, app_dic, rescan, api):
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{app_dic["md5"]}.so'  # NEW FILENAME
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
    else:
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        append_scan_status(checksum, 'init')
        # Analysis starts here
        app_dic['size'] = f'{str(file_size(app_dic["app_path"]))}MB'
        app_dic['sha1'], app_dic['sha256'] = hash_gen(
            checksum,
            app_dic['app_path'])
        app_dic['files'] = []
        app_dic['certz'] = []
        app_dic['playstore'] = {'error': True}
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
            'network_security': {
                'network_findings': [],
                'network_summary': {},
            },
            'malware_permissions': {},
        }
        cert_dic = {
            'certificate_info': '',
            'certificate_findings': [],
            'certificate_summary': {},
        }
        app_dic['real_name'] = ''
        elf_dict = library_analysis(
            checksum,
            app_dic['app_dir'],
            'elf')
        # File Analysis is used to store symbols from so
        app_dic['certz'] = get_symbols(
            elf_dict['elf_symbols'])
        apkid_results = {}
        code_an_dic = {
            'api': {},
            'perm_mappings': {},
            'findings': {},
            'niap': {},
            'urls_list': [],
            'urls': [],
            'emails': [],
        }
        quark_results = []
        # Get the strings and metadata from shared object
        get_strings_metadata(
            checksum,
            None,
            None,
            elf_dict['elf_strings'],
            None,
            None,
            code_an_dic)
        # Firebase DB Check
        code_an_dic['firebase'] = firebase_analysis(
            checksum,
            code_an_dic['urls_list'])
        # Domain Extraction and Malware Check
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_an_dic['urls_list'])
        # Extract Trackers from Domains
        trk = Trackers.Trackers(
            checksum,
            None,
            app_dic['tools_dir'])
        trackers = trk.get_trackers_domains_or_deps(
            code_an_dic['domains'], [])
        app_dic['zipped'] = 'so'
        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_an_dic,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            quark_results,
            trackers,
            rescan,
        )
    context['appsec'] = {}
    context['average_cvss'] = None
    context['dynamic_analysis_done'] = False
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(
            app_dic['app_path'])
    template = 'static_analysis/android_binary_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)
