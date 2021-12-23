# -*- coding: utf_8 -*-
"""Security tests on data in transit."""
import re
import logging
import threading
from json import dump
from pathlib import Path

from django.conf import settings

from mobsf.DynamicAnalyzer.views.android.frida_core import (
    Frida,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    get_traffic,
    stop_httptools,
)


HTTPS = re.compile(r'(GET|POST|HEAD|PUT|DELETE|'
                   r'CONNECT|OPTIONS|TRACE|PATCH) https:\/\/')
HTTP = re.compile(r'(GET|POST|HEAD|PUT|DELETE|'
                  r'CONNECT|OPTIONS|TRACE|PATCH) http:\/\/')
logger = logging.getLogger(__name__)


def detect_traffic(data):
    """Detect Traffic."""
    status = {
        'http': False,
        'https': False,
    }
    if not data:
        return status
    if HTTPS.search(data):
        status['https'] = True
    if HTTP.search(data):
        status['http'] = True
    return status


def run_tls_tests(request, md5_hash, env, package, test_pkg, duration):
    """Run all TLS test cases."""
    test_status = {
        'tls_misconfigured': False,
        'no_tls_pin_or_transparency': False,
        'pin_or_transparency_bypassed': False,
        'has_cleartext': False,
    }
    version = env.get_android_version()
    env.enable_adb_reverse_tcp(version)
    env.set_global_proxy(version)
    # Test 1: Remove Root CA, Run App, No TLS Pinning Bypass
    env.adb_command(['am', 'force-stop', package], True)
    logger.info('Running TLS Misconfiguration Test')
    env.configure_proxy(test_pkg, request)
    env.install_mobsf_ca('remove')
    env.run_app(package)
    env.wait(duration)
    stop_httptools(get_http_tools_url(request))
    traffic = get_traffic(test_pkg)
    res = detect_traffic(traffic)
    if res['http']:
        test_status['has_cleartext'] = True
    if res['https']:
        test_status['tls_misconfigured'] = True
    # Test 2: Install Root CA, Run App, No TLS Pinning Bypass
    env.adb_command(['am', 'force-stop', package], True)
    logger.info('Running TLS Pinning/Certificate Transparency Test')
    env.configure_proxy(test_pkg, request)
    env.run_app(package)
    env.wait(duration)
    stop_httptools(get_http_tools_url(request))
    traffic = get_traffic(test_pkg)
    res = detect_traffic(traffic)
    if res['http']:
        test_status['has_cleartext'] = True
    if res['https']:
        test_status['no_tls_pin_or_transparency'] = True
    # Test 3: MobSF TLS Pinning Bypass Check
    env.adb_command(['am', 'force-stop', package], True)
    logger.info('Running TLS Pinning/Certificate Transparency Bypass Test')
    env.configure_proxy(test_pkg, request)
    frd = Frida(
        md5_hash,
        package,
        ['ssl_pinning_bypass', 'debugger_check_bypass', 'root_bypass'],
        None,
        None,
        None,
    )
    trd = threading.Thread(target=frd.connect)
    trd.daemon = True
    trd.start()
    env.wait(duration)
    stop_httptools(get_http_tools_url(request))
    traffic = get_traffic(test_pkg)
    res = detect_traffic(traffic)
    if res['http']:
        test_status['has_cleartext'] = True
    if res['https']:
        test_status['pin_or_transparency_bypassed'] = True
    env.adb_command(['am', 'force-stop', package], True)
    out = Path(settings.UPLD_DIR) / md5_hash / 'mobsf_tls_tests.json'
    with out.open('w', encoding='utf-8') as target:
        dump(test_status, target)
    return test_status
