# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
import os
from pathlib import Path
from threading import Thread

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    common_check,
    get_md5,
    print_n_send_error_response,
    python_dict,
    strict_package_check,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.DynamicAnalyzer.forms import UploadFileForm
from mobsf.DynamicAnalyzer.views.ios.corellium_ssh import (
    generate_keypair_if_not_exists,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    start_proxy,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumAPI,
    CorelliumInstanceAPI,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_ssh import (
    ssh_jumphost_reverse_port_forward,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)


@login_required
@permission_required(Permissions.SCAN)
def dynamic_analysis(request, api=False):
    """The iOS Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        ipas = StaticAnalyzerIOS.objects.filter(
            FILE_NAME__endswith='.ipa')
        for ipa in reversed(ipas):
            bundle_hash = get_md5(ipa.BUNDLE_ID.encode('utf-8'))
            frida_dump = Path(
                settings.UPLD_DIR) / bundle_hash / 'mobsf_dump_file.txt'
            macho = python_dict(ipa.MACHO_ANALYSIS)
            encrypted = False
            if (macho
                    and macho.get('encrypted')
                    and macho.get('encrypted').get('is_encrypted')):
                encrypted = macho['encrypted']['is_encrypted']
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
        c = CorelliumAPI(getattr(settings, 'CORELLIUM_PROJECT_ID', ''))
        corellium_auth = c.api_ready() and c.api_auth()
        if corellium_auth and c.get_projects():
            instances = c.get_instances()
            project_id = c.project_id
            setup_ssh_keys(c)
        context = {'apps': scan_apps,
                   'dynamic_analyzer': corellium_auth,
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


@login_required
@permission_required(Permissions.SCAN)
def dynamic_analyzer(request, api=False):
    """Dynamic Analyzer for in-device iOS apps."""
    try:
        if api:
            bundleid = request.POST.get('bundle_id')
        else:
            bundleid = request.GET.get('bundleid')
        if not bundleid or not strict_package_check(bundleid):
            return print_n_send_error_response(
                request,
                'Invalid iOS Bundle id',
                api)
        if api:
            instance_id = request.POST.get('instance_id')
        else:
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
        ci = CorelliumInstanceAPI(instance_id)
        configure_proxy(request, bundleid, ci)
        if api:
            form = None
        else:
            form = UploadFileForm()
        context = {
            'hash': bundle_hash,
            'instance_id': instance_id,
            'bundle_id': bundleid,
            'version': settings.MOBSF_VER,
            'form': form,
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


def setup_ssh_keys(c):
    # Get Authorized keys for the project
    pkeys = c.get_authorized_keys()
    location = Path(settings.UPLD_DIR).parent
    _prv, pub = generate_keypair_if_not_exists(location)
    add_keys = False
    is_docker = os.getenv('MOBSF_PLATFORM') == 'docker'
    if not pkeys:
        # No SSH Keys associated with the project
        # let's add one
        add_keys = True
    else:
        # SSH Keys are already associated with the project
        # Check if our key is associated
        pub_key_exists = False
        for pkey in pkeys:
            if pkey['project'] == c.project_id:
                rkey = get_md5(pkey['key'].encode('utf-8'))
                if rkey == get_md5(pub):
                    pub_key_exists = True
                    break
            if is_docker and pkey['label'].endswith('(docker)'):
                # Delete all docker generated keys
                # This is done to avoid multiple stale keys being
                # added on each run.
                logger.info('Removing old stale SSH public key')
                c.delete_authorized_key(pkey['identifier'])
        # Our key is not asscoiated with the project, let's add it
        if not pub_key_exists:
            add_keys = True
    if add_keys:
        iden = c.add_authorized_key(pub)
        if not iden:
            logger.error('Failed to add SSH Key to Corellium project')
            return
        logger.info('Added SSH Key to Corellium project')


def configure_proxy(request, project, ci):
    """Configure HTTPS Proxy."""
    proxy_port = settings.PROXY_PORT
    logger.info('Starting HTTPS Proxy on %s', proxy_port)
    stop_httptools(get_http_tools_url(request))
    start_proxy(proxy_port, project)
    # Remote Port forward for HTTPS Proxy
    logger.info('Starting Remote Port Forward over SSH')
    Thread(target=ssh_jumphost_reverse_port_forward,
           args=(ci.get_ssh_connection_string(),),
           daemon=True).start()
