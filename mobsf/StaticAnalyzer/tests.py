#!/usr/bin/env python
import io
import json
import logging
import os
import platform
from pathlib import Path
from types import SimpleNamespace

from mobsf.MobSF.init import api_key
from mobsf.MobSF.utils import (
    get_android_src_dir,
    is_dex_magic,
)
from mobsf.MobSF.views.helpers import FileType
from mobsf.StaticAnalyzer.views.common.appsec import (
    calculate_security_score,
)
from mobsf.StaticAnalyzer.views.common.binary.macho import (
    MachOChecksec,
    is_debug_symbol_stripped,
)
from mobsf.StaticAnalyzer.views.common.pdf import (
    get_pdf_resource_policy,
    render_html_to_pdf,
)
from mobsf.StaticAnalyzer.views.ios.app_transport_security import (
    check_transport_security,
)
from mobsf.StaticAnalyzer.views.ios.binary_rule_matcher import (
    binary_rule_matcher,
)
from mobsf.StaticAnalyzer.views.ios.classdump import (
    classdump_lief,
)
from mobsf.StaticAnalyzer.views.ios.entitlements import (
    evaluate_entitlements,
    ipa_entitlements_analysis,
)
from mobsf.StaticAnalyzer.views.ios.ipa import (
    get_embedded_framework_deps,
)

from django.conf import settings
from django.http import HttpResponse
from django.test import Client, SimpleTestCase, TestCase

logger = logging.getLogger(__name__)

RESCAN = False
# Set RESCAN to True if Static Analyzer Code is modified
EXTS = settings.ANDROID_EXTS + settings.IOS_EXTS + settings.WINDOWS_EXTS


def static_analysis_test():
    """Test Static Analyzer."""
    logger.info('Running Static Analyzer Unit test')
    try:
        uploaded = []
        logger.info('Running Upload Test')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            if not filename.endswith(EXTS):
                continue
            if platform.system() == 'Windows' and filename.endswith('.ipa'):
                continue
            fpath = os.path.join(apk_dir, filename)
            with open(fpath, 'rb') as file_pointer:
                response = http_client.post(
                    '/upload/',
                    {'file': file_pointer})
                obj = json.loads(response.content.decode('utf-8'))
                if response.status_code == 200 and obj['status'] == 'success':
                    logger.info('[OK] Upload OK: %s', filename)
                    uploaded.append(obj)
                else:
                    logger.error('Performing Upload: %s', filename)
                    return True
        logger.info('[OK] Completed Upload test')
        logger.info('Running Static Analysis Test')
        for upl in uploaded:
            scan_url = '/{}/{}/'.format(
                upl['analyzer'],
                upl['hash'])
            if RESCAN:
                scan_url = scan_url + '?rescan=1'
            resp = http_client.get(scan_url, follow=True)
            if resp.status_code == 200:
                logger.info('[OK] Static Analysis Complete: %s', scan_url)
            else:
                logger.error('Performing Static Analysis: %s', scan_url)
                return True
        logger.info('[OK] Static Analysis test completed')
        logger.info('Running PDF Generation Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                '/pdf/02e7989c457ab67eb514a8328779f256/',
                '/pdf/82ab8b2193b3cfb1c737e3a786be363a/',
                '/pdf/6c23c2970551be15f32bbab0b5db0c71/',
                '/pdf/52c50ae824e329ba8b5b7a0f523efffe/',
                '/pdf/57bb5be0ea44a755ada4a93885c3825e/',
                '/pdf/8179b557433835827a70510584f3143e/',
                '/pdf/7b0a23bffc80bac05739ea1af898daad/',
            ]
        else:
            pdfs = [
                '/pdf/02e7989c457ab67eb514a8328779f256/',
                '/pdf/82ab8b2193b3cfb1c737e3a786be363a/',
                '/pdf/52c50ae824e329ba8b5b7a0f523efffe/',
                '/pdf/57bb5be0ea44a755ada4a93885c3825e/',
                '/pdf/8179b557433835827a70510584f3143e/',
                '/pdf/7b0a23bffc80bac05739ea1af898daad/',
            ]

        for pdf in pdfs:
            resp = http_client.get(pdf)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == 'application/pdf'):
                logger.info('[OK] PDF Report Generated: %s', pdf)
            else:
                logger.error('Generating PDF: %s', pdf)
                logger.info(resp.content)
                return True
        logger.info('[OK] PDF Generation test completed')

        # Compare apps test
        logger.info('Running App Compare tests')
        first_app = '82ab8b2193b3cfb1c737e3a786be363a'
        second_app = '52c50ae824e329ba8b5b7a0f523efffe'
        url = '/compare/{}/{}/'.format(first_app, second_app)
        resp = http_client.get(url, follow=True)
        assert (resp.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] App compare tests passed successfully')
        else:
            logger.error('App compare tests failed')
            logger.info(resp.content)
            return True

        # Scan shared object or dylib from binaries.
        logger.info('Running Library Analysis test')
        md5 = '82ab8b2193b3cfb1c737e3a786be363a'
        lib = 'apktool_out/lib/arm64-v8a/libdivajni.so'
        url = f'/scan_library/{md5}?library={lib}'
        resp = http_client.get(url, follow=True)
        assert (resp.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] Library Analysis test passed successfully')
        else:
            logger.error('Library Analysis test failed')
            logger.info(resp.content)
            return True

        # Search by MD5 and text
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad']
        else:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad']
        # Search by text
        queries = [
            'diva',
            'webview',
        ]
        logger.info('Running Search test')
        for q in scan_md5s + queries:
            url = f'/search?query={q}'
            resp = http_client.get(url, follow=True)
            assert (resp.status_code == 200)
            if resp.status_code == 200:
                logger.info('[OK] Search by query test passed for %s', q)
            else:
                logger.error('Search by query test failed for %s', q)
                logger.info(resp.content)
                return True
        logger.info('[OK] Search by MD5 and text tests completed')

        # Deleting Scan Results
        logger.info('Running Delete Scan Results test')
        for md5 in scan_md5s:
            resp = http_client.post('/delete_scan/', {'md5': md5})
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['deleted'] == 'yes':
                    logger.info('[OK] Deleted Scan: %s', md5)
                else:
                    logger.error('Deleting Scan: %s', md5)
                    return True
            else:
                logger.error('Deleting Scan: %s', md5)
                return True
        logger.info('Delete Scan Results test completed')
    except Exception:
        logger.exception('Completing Static Analyzer Test')
        return True
    return False


def api_test():
    """View for Handling REST API Test."""
    logger.info('\nRunning REST API Unit test')
    auth = api_key(settings.MOBSF_HOME)
    try:
        uploaded = []
        logger.info('Running Test on Upload API')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            if not filename.endswith(EXTS):
                continue
            if platform.system() == 'Windows' and filename.endswith('.ipa'):
                continue
            fpath = os.path.join(apk_dir, filename)
            if (platform.system() not in ['Darwin', 'Linux']
                    and fpath.endswith('.ipa')):
                continue
            with open(fpath, 'rb') as file_pointer:
                response = http_client.post(
                    '/api/v1/upload',
                    {'file': file_pointer},
                    HTTP_AUTHORIZATION=auth)
                obj = json.loads(response.content.decode('utf-8'))
                if response.status_code == 200 and 'hash' in obj:
                    logger.info('[OK] Upload OK: %s', filename)
                    uploaded.append(obj)
                else:
                    logger.error('Performing Upload %s', filename)
                    return True
        logger.info('[OK] Completed Upload API test')
        logger.info('Running Static Analysis API Test')
        for upl in uploaded:
            resp = http_client.post(
                '/api/v1/scan',
                {'hash': upl['hash']},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logger.info('[OK] Static Analysis Complete: %s',
                            upl['file_name'])
            else:
                logger.error('Performing Static Analysis: %s',
                             upl['file_name'])
                return True
        logger.info('[OK] Static Analysis API test completed')
        # Scan List API test
        logger.info('Running Scan List API tests')
        resp = http_client.get('/api/v1/scans', HTTP_AUTHORIZATION=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test 1 success')
        else:
            logger.error('Scan List API Test 1')
            return True
        resp = http_client.get(
            '/api/v1/scans?page=1&page_size=10', HTTP_AUTHORIZATION=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test 2 success')
        else:
            logger.error('Scan List API Test 2')
            return True
        resp = http_client.get('/api/v1/scans', HTTP_X_MOBSF_API_KEY=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test with custom http header 1 success')
        else:
            logger.error('Scan List API Test with custom http header 1')
            return True
        resp = http_client.get(
            '/api/v1/scans?page=1&page_size=10', HTTP_X_MOBSF_API_KEY=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test with custom http header 2 success')
        else:
            logger.error('Scan List API Test with custom http header 2')
            return True
        logger.info('[OK] Scan List API tests completed')
        # Scan logs tests
        logger.info('Running Scan Logs API tests')
        for upl in uploaded:
            resp = http_client.post(
                '/api/v1/scan_logs',
                {'hash': upl['hash']},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logs = json.loads(resp.content.decode('utf-8'))
                if 'logs' in logs and len(logs['logs']) > 0:
                    logger.info('[OK] Scan Logs API test: %s', upl['hash'])
            else:
                logger.error('Scan Logs API test: %s', upl['hash'])
                return True
        logger.info('[OK] Static Analysis API test completed')
        # Search API Tests
        logger.info('Running Search API tests')
        for term in ['diva', 'webview', '52c50ae824e329ba8b5b7a0f523efffe']:
            resp = http_client.post(
                '/api/v1/search',
                {'query': term},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logger.info('[OK] Search API test: %s', term)
            else:
                logger.error('Search API test: %s', term)
                return True
        # PDF Tests
        logger.info('Running PDF Generation API Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                {'hash': '02e7989c457ab67eb514a8328779f256'},
                {'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                {'hash': '6c23c2970551be15f32bbab0b5db0c71'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e'},
                {'hash': '8179b557433835827a70510584f3143e'},
                {'hash': '7b0a23bffc80bac05739ea1af898daad'},
            ]
        else:
            pdfs = [
                {'hash': '02e7989c457ab67eb514a8328779f256'},
                {'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e'},
                {'hash': '8179b557433835827a70510584f3143e'},
                {'hash': '7b0a23bffc80bac05739ea1af898daad'},
            ]
        for pdf in pdfs:
            resp = http_client.post(
                '/api/v1/download_pdf', pdf, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/download_pdf', pdf, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == 'application/pdf'):
                logger.info('[OK] PDF Report Generated: %s', pdf['hash'])
            else:
                logger.error('Generating PDF: %s', pdf['hash'])
                logger.info(resp.content)
                return True
        logger.info('[OK] PDF Generation API test completed')
        logger.info('Running JSON Report API test')
        # JSON Report
        ctype = 'application/json; charset=utf-8'
        for jsn in pdfs:
            resp = http_client.post(
                '/api/v1/report_json', jsn, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/report_json', jsn, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == ctype):
                logger.info('[OK] JSON Report Generated: %s', jsn['hash'])
            else:
                logger.error('Generating JSON Response: %s', jsn['hash'])
                return True
        logger.info('[OK] JSON Report API test completed')
        logger.info('Running Scorecard API test')
        # Scorecard Report
        for scr in pdfs:
            if scr['hash'] == '8179b557433835827a70510584f3143e':
                # Windows Scorecard not yet implemented
                continue
            resp = http_client.post(
                '/api/v1/scorecard', scr, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/scorecard', scr, HTTP_X_MOBSF_API_KEY=auth)
            if resp.status_code == 200 and resp_custom.status_code == 200:
                rp = json.loads(resp.content.decode('utf-8'))
                if 'security_score' in rp:
                    logger.info(
                        '[OK] Security Score - %s', rp['security_score'])
                else:
                    logger.error('Security Score Failed - %s', str(rp))
                    return True
            else:
                logger.error('Scorecard API Failed for - %s', scr['hash'])
                return True
        logger.info('[OK] Scorecard API test completed')
        logger.info('Running View Source API test')
        # View Source tests
        files = [{'file': 'jakhar/aseem/diva/MainActivity.java',
                  'type': 'apk',
                  'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                 {'file': 'AndroidManifest.xml',
                  'type': 'xml',
                  'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                 {'file': 'opensecurity/webviewignoressl/MainActivity.java',
                  'type': 'studio',
                  'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                 {'file': 'DamnVulnerableIOSApp/AppDelegate.m',
                  'type': 'ios',
                  'hash': '57bb5be0ea44a755ada4a93885c3825e'}]
        if platform.system() in ['Darwin', 'Linux']:
            files.append({
                'file': 'helloworld.app/Info.plist',
                'type': 'ipa',
                'hash': '6c23c2970551be15f32bbab0b5db0c71'})
        for sfile in files:
            resp = http_client.post(
                '/api/v1/view_source', sfile, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/view_source', sfile, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['title']:
                    logger.info('[OK] Reading - %s', sfile['file'])
                else:
                    logger.error('Reading - %s', sfile['file'])
                    return True
            else:
                logger.error('Reading - %s', sfile['file'])
                return True
        logger.info('[OK] View Source API test completed')
        # Compare apps test
        logger.info('Running App Compare API tests')
        resp = http_client.post(
            '/api/v1/compare',
            {
                'hash1': '82ab8b2193b3cfb1c737e3a786be363a',
                'hash2': '52c50ae824e329ba8b5b7a0f523efffe',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp_custom = http_client.post(
            '/api/v1/compare',
            {
                'hash1': '82ab8b2193b3cfb1c737e3a786be363a',
                'hash2': '52c50ae824e329ba8b5b7a0f523efffe',
            },
            HTTP_X_MOBSF_API_KEY=auth)
        assert (resp_custom.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] App compare API tests completed')
        else:
            logger.error('App compare API tests failed')
            logger.info(resp.content)
            return True
        logger.info('Running Delete Scan Results test')
        # Suppression tests
        # Android Manifest by rule
        and_hash = '82ab8b2193b3cfb1c737e3a786be363a'
        rule = 'app_is_debuggable'
        typ = 'manifest'
        logger.info('Running Suppression disable by rule for APK manifest')
        resp = http_client.post(
            '/api/v1/suppress_by_rule',
            {
                'hash': and_hash,
                'type': typ,
                'rule': rule,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = json.loads(resp.content.decode('utf-8'))
        if dat['status'] == 'ok':
            logger.info('[OK] Suppression by rule - %s', rule)
        else:
            logger.error('[ERROR] Suppression by rule - %s', rule)
            return True
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': and_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule in dat:
            logger.info('[OK] Listing suppression for - %s', and_hash)
        else:
            logger.error('[ERROR] Listing suppression for  - %s', and_hash)
            return True
        resp = http_client.post(
            '/api/v1/delete_suppression',
            {
                'hash': and_hash,
                'type': typ,
                'rule': rule,
                'kind': 'rule',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': and_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule not in dat:
            logger.info('[OK] Suppression deleted - %s', and_hash)
        else:
            logger.error('[ERROR] Suppression deletion - %s', and_hash)
            return True
        # iOS Code by Files
        ios_hash = '57bb5be0ea44a755ada4a93885c3825e'
        rule = 'ios_app_logging'
        typ = 'code'
        sfile = ('DamnVulnerableIOSApp/Cocoa'
                 'Lumberjack/DDAbstractDatabaseLogger.m')
        logger.info('Running Suppression by files for iOS ObjC source')
        resp = http_client.post(
            '/api/v1/suppress_by_files',
            {
                'hash': ios_hash,
                'type': typ,
                'rule': rule,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = json.loads(resp.content.decode('utf-8'))
        if dat['status'] == 'ok':
            logger.info('[OK] Suppression by files for - %s', rule)
        else:
            logger.error('[ERROR] Suppression by files for - %s', rule)
            return True
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': ios_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule in dat and sfile in dat:
            logger.info('[OK] Listing suppression for - %s', ios_hash)
        else:
            logger.error('[ERROR] Listing suppression for  - %s', ios_hash)
            return True
        resp = http_client.post(
            '/api/v1/delete_suppression',
            {
                'hash': ios_hash,
                'type': typ,
                'rule': rule,
                'kind': 'file',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': ios_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule not in dat:
            logger.info('[OK] Suppression deleted - %s', ios_hash)
        else:
            logger.error('[ERROR] Suppression deletion - %s', ios_hash)
            return True
        # Deleting Scan Results
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad',
                         ]
        else:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad',
                         ]
        for md5 in scan_md5s:
            resp = http_client.post(
                '/api/v1/delete_scan', {'hash': md5}, HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['deleted'] == 'yes':
                    logger.info('[OK] Deleted Scan: %s', md5)
                else:
                    logger.error('Deleting Scan: %s', md5)
                    return True
            else:
                logger.error('Deleting Scan: %s', md5)
                return True
        logger.info('Delete Scan Results API test completed')
    except Exception:
        logger.exception('Completing REST API Unit Test')
        return True
    return False


def start_test(request):
    """Static Analyzer Unit test."""
    item = request.GET.get('module', 'static')
    if item == 'static':
        comp = 'static_analyzer'
        failed_stat = static_analysis_test()
    else:
        comp = 'static_analyzer_api'
        failed_stat = api_test()
    try:
        if failed_stat:
            message = 'some tests failed'
            resp_code = 403
        else:
            message = 'all tests completed'
            resp_code = 200
    except Exception:
        resp_code = 403
        message = 'error'
    logger.info('\n\nALL TESTS COMPLETED!')
    logger.info('Test Status: %s', message)
    return HttpResponse(json.dumps({comp: message}),
                        content_type='application/json; charset=utf-8',
                        status=resp_code)


class StaticAnalyzerAndAPI(TestCase):
    """Unit Tests."""

    def setUp(self):
        self.http_client = Client()

    def test_static_analyzer(self):
        resp = self.http_client.post('/tests/?module=static')
        self.assertEqual(resp.status_code, 200)

    def test_rest_api(self):
        resp = self.http_client.post('/tests/?module=api')
        self.assertEqual(resp.status_code, 200)


def _symbols(*entries):
    return [SimpleNamespace(name=n, raw_type=t) for n, t in entries]


class MachODebugSymbolStripped(SimpleTestCase):
    """Mach-O debug symbol strip detection."""

    def test_debug_build(self):
        syms = _symbols(
            ('_helper', 0x0e),
            ('', 0x64),
            ('main.c', 0x64),
            ('/tmp/main.o', 0x66),
            ('_main', 0x24),
            ('_main', 0x0f))
        self.assertFalse(is_debug_symbol_stripped(syms))

    def test_debug_build_without_local_symbols(self):
        syms = _symbols(
            ('', 0x64),
            ('/tmp/bar.o', 0x66),
            ('_only_exported', 0x24),
            ('_only_exported', 0x0f))
        self.assertFalse(is_debug_symbol_stripped(syms))

    def test_strip_debugging_symbols_only(self):
        syms = _symbols(
            ('_helper', 0x0e),
            ('__mh_execute_header', 0x0f),
            ('_main', 0x0f),
            ('_printf', 0x01))
        self.assertTrue(is_debug_symbol_stripped(syms))

    def test_strip_non_global_symbols(self):
        syms = _symbols(('_foo_exported', 0x0f))
        self.assertTrue(is_debug_symbol_stripped(syms))

    def test_strip_all_symbols(self):
        syms = _symbols(
            ('radr://5614542', 0x3c),
            ('__mh_execute_header', 0x0f),
            ('_printf', 0x01))
        self.assertTrue(is_debug_symbol_stripped(syms))

    def test_no_symbols(self):
        self.assertTrue(is_debug_symbol_stripped([]))

    def test_stripped_dylib_with_local_symbols(self):
        dylib = Path(settings.BASE_DIR) / 'StaticAnalyzer/test_files/macho.dylib'
        self.assertTrue(MachOChecksec(dylib).is_symbols_stripped())


class SecurityScoreTests(SimpleTestCase):
    """AppSec security score monotonicity and scaling tests."""

    def test_no_findings_scores_100(self):
        self.assertEqual(calculate_security_score(0, 0, 0), 100)
        self.assertEqual(calculate_security_score(0, 0, 5), 100)

    def test_single_high_does_not_zero_score(self):
        self.assertEqual(calculate_security_score(1, 0, 0), 85)

    def test_fixing_warnings_increases_score(self):
        before = calculate_security_score(4, 11, 2)
        after = calculate_security_score(4, 8, 2)
        self.assertGreater(after, before)

    def test_fewer_findings_scores_higher_independent_of_secure_count(self):
        fewer = calculate_security_score(3, 5, 2)
        more_with_high_sec = calculate_security_score(4, 6, 8)
        much_more = calculate_security_score(9, 15, 8)
        self.assertGreater(fewer, more_with_high_sec)
        self.assertGreater(more_with_high_sec, much_more)

    def test_score_is_non_decreasing_and_approaches_floor(self):
        self.assertGreaterEqual(
            calculate_security_score(4, 29, 2),
            calculate_security_score(4, 30, 2),
        )
        self.assertGreater(
            calculate_security_score(50, 0, 0),
            calculate_security_score(100, 0, 0),
        )
        self.assertGreaterEqual(calculate_security_score(1000, 1000, 0), 10)


class DexFileSupportTests(SimpleTestCase):
    """Direct DEX upload and magic byte validation tests."""

    def test_valid_dex_magic(self):
        buf = io.BytesIO(b'dex\n039\x00' + b'\x00' * 32)
        self.assertTrue(is_dex_magic(buf))
        self.assertEqual(buf.tell(), 0)

    def test_invalid_dex_magic(self):
        for payload in (b'PK\x03\x04', b'dex\n03a\x00', b'dex\n035\x01', b'dex'):
            buf = io.BytesIO(payload)
            self.assertFalse(is_dex_magic(buf))

    def test_filetype_accepts_valid_dex_and_rejects_mismatched_magic(self):
        valid_obj = io.BytesIO(b'dex\n035\x00' + b'\x00' * 32)
        valid_obj.name = 'classes.dex'
        valid_obj.content_type = 'application/octet-stream'
        ft = FileType(valid_obj)
        self.assertTrue(ft.is_dex())
        self.assertTrue(ft.is_allow_file())

        invalid_obj = io.BytesIO(b'PK\x03\x04' + b'\x00' * 32)
        invalid_obj.name = 'classes.dex'
        invalid_obj.content_type = 'application/octet-stream'
        ft_invalid = FileType(invalid_obj)
        self.assertFalse(ft_invalid.is_allow_file())

    def test_get_android_src_dir_for_dex(self):
        base = Path('/tmp/mobsf_test')
        self.assertEqual(get_android_src_dir(base, 'dex'), base / 'java_source')


class PdfGenerationSecurityTests(SimpleTestCase):
    """Tests for xhtml2pdf generation and ResourceAccessPolicy confinement."""

    def test_render_html_to_pdf_produces_valid_pdf(self):
        pdf_bytes = render_html_to_pdf(
            '<html><body><h1>MobSF Report</h1></body></html>')
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))

    def test_pdf_resource_policy_blocks_remote_and_outside_paths(self):
        from xhtml2pdf.files import ResourceAccessError
        policy = get_pdf_resource_policy()
        with self.assertRaises(ResourceAccessError):
            policy.check_url('https://evil.example/a.css')
        with self.assertRaises(ResourceAccessError):
            policy.check_path('/etc/passwd')
        with self.assertRaises(ResourceAccessError):
            policy.check_path(Path(settings.BASE_DIR) / 'MobSF' / 'settings.py')

    def test_pdf_resource_policy_allows_static_and_download_roots(self):
        policy = get_pdf_resource_policy()
        css_path = Path(settings.BASE_DIR) / 'static' / \
            'others' / 'css' / 'pdf_report.css'
        policy.check_path(css_path)
        policy.check_path(Path(settings.DWD_DIR))


class IOSEntitlementsAnalysisTests(SimpleTestCase):
    """Tests for iOS Entitlements and Provisioning Profile security checks."""

    def test_evaluate_entitlements_flags_high_and_warning_conditions(self):
        entitlements = {
            'get-task-allow': True,
            'com.apple.private.security.no-sandbox': True,
            'keychain-access-groups': ['TEAM123.*'],
            'com.apple.security.application-groups': ['group.com.example.shared'],
            'com.apple.developer.associated-domains': [
                'applinks:*.example.com?mode=developer',
            ],
        }
        profile = {'provisions_all_devices': True, 'team_id': 'TEAM123'}
        results = {
            rule_id: (title, desc, meta)
            for rule_id, title, desc, meta in evaluate_entitlements(
                entitlements, profile)
        }
        self.assertEqual(
            results['ios_entitlement_debuggable'][2]['severity'], 'high')
        self.assertEqual(
            results['ios_entitlement_dangerous'][2]['severity'], 'high')
        self.assertEqual(
            results['ios_enterprise_provisioning'][2]['severity'], 'warning')
        self.assertEqual(
            results['ios_keychain_wildcard'][2]['severity'], 'warning')
        self.assertEqual(
            results['ios_app_groups_shared'][2]['severity'], 'info')
        self.assertEqual(
            results['ios_associated_domains_wildcard'][2]['severity'],
            'warning',
        )

    def test_ipa_entitlements_analysis_on_sample_ipa(self):
        import tempfile
        import zipfile
        from unittest import mock
        ipa_path = Path(settings.BASE_DIR) / 'StaticAnalyzer/test_files/ios.ipa'
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(ipa_path) as zf:
                zf.extractall(tmp)
            app_root = Path(tmp) / 'Payload' / 'helloworld.app'
            bin_path = app_root / 'helloworld'
            findings = {}
            with mock.patch(
                'mobsf.StaticAnalyzer.views.ios.entitlements.append_scan_status',
            ):
                cs_info = ipa_entitlements_analysis(
                    '0' * 32, findings, app_root, bin_path)
            self.assertIn(
                'Application is provisioned for Enterprise / '
                'All-Devices distribution',
                findings,
            )
            self.assertIn('Signer:', cs_info)
            self.assertIn('application-identifier:', cs_info)
            self.assertNotIn(
                'Application uses a wildcard Keychain access group',
                findings,
            )


class IOSBinaryRulesAndClassdumpTests(SimpleTestCase):
    """Tests for iOS binary regex rules and LIEF Objective-C/Swift classdump."""

    def test_binary_rule_matcher_matches_last_symbol_and_modern_ios_rules(self):
        findings = {}
        symbols = [
            '_NSLog',
            '_srand',
            '_malloc',
            '_kSecAttrAccessibleAlways',
            '_sqlite3_exec',
            '_OBJC_CLASS_$_UIWebView',
            '_gets',
        ]
        classdump = (
            b'setAllowsAnyHTTPSCertificate:forHost:\n'
            b'setAllowFileAccessFromFileURLs:\n'
            b'generalPasteboard\n'
        )
        binary_rule_matcher('0' * 32, findings, symbols, classdump)
        self.assertIn('Binary makes use of insecure API(s)', findings)
        self.assertIn(
            '_gets',
            findings['Binary makes use of insecure API(s)']['detailed_desc'],
        )
        self.assertIn(
            'Binary makes use of the insecure Random function(s)', findings)
        self.assertIn('Binary makes use of Logging function', findings)
        self.assertIn('Binary makes use of malloc function', findings)
        self.assertEqual(
            findings[
                'Binary references insecure SSL/TLS certificate '
                'validation API(s)'
            ]['severity'],
            'high',
        )
        self.assertEqual(
            findings[
                'Binary references weak Keychain accessibility attribute(s)'
            ]['severity'],
            'warning',
        )
        self.assertEqual(
            findings[
                'Binary references dangerous WKWebView file access selector(s)'
            ]['severity'],
            'warning',
        )
        self.assertEqual(
            findings['Binary uses deprecated UIWebView Component']['severity'],
            'warning',
        )
        self.assertIn('Binary makes use of UIPasteboard', findings)
        self.assertIn('Binary makes use of SQLite API(s)', findings)

    def test_classdump_lief_extracts_objc_classes_and_selectors(self):
        import tempfile
        import zipfile
        ipa_path = Path(settings.BASE_DIR) / 'StaticAnalyzer/test_files/ios.ipa'
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(ipa_path) as zf:
                zf.extractall(tmp)
            bin_path = Path(tmp) / 'Payload' / 'helloworld.app' / 'helloworld'
            dump = classdump_lief(bin_path.as_posix())
            self.assertIn(b'AppDelegate', dump)
            self.assertIn(b'application:didFinishLaunchingWithOptions:', dump)


class IOSPlistAndFrameworkTrackerTests(SimpleTestCase):
    """Tests for iOS Info.plist file-sharing checks, TLSv1.2 ATS, and frameworks."""

    def test_check_transport_security_tlsv12_is_info_and_file_sharing_flagged(self):
        plist_data = {
            'UIFileSharingEnabled': True,
            'LSSupportsOpeningDocumentsInPlace': True,
            'NSAppTransportSecurity': {
                'NSExceptionDomains': {
                    'api.example.com': {
                        'NSExceptionMinimumTLSVersion': 'TLSv1.2',
                        'NSRequiresCertificateTransparency': 'YES',
                    },
                },
            },
        }
        findings = {
            item['issue']: item
            for item in check_transport_security(plist_data)
        }
        self.assertEqual(
            findings[
                'NSExceptionMinimumTLSVersion set to TLSv1.2 on api.example.com'
            ]['severity'],
            'info',
        )
        self.assertEqual(
            findings[
                'iTunes / Finder File Sharing is enabled '
                '(UIFileSharingEnabled)'
            ]['severity'],
            'warning',
        )
        self.assertEqual(
            findings[
                'Opening documents in place is enabled '
                '(LSSupportsOpeningDocumentsInPlace)'
            ]['severity'],
            'warning',
        )

    def test_get_embedded_framework_deps_extracts_bundle_identifiers(self):
        import plistlib
        import tempfile
        from unittest import mock
        from mobsf.MalwareAnalyzer.views.Trackers import Trackers
        with tempfile.TemporaryDirectory() as tmp:
            app_root = Path(tmp) / 'Payload' / 'App.app'
            for fw_name, bid in (
                ('AppsFlyerLib.framework', 'com.appsflyer.AppsFlyerLib'),
                ('FirebaseAnalytics.framework', 'org.cocoapods.FirebaseAnalytics'),
                ('Adjust.framework', 'com.adjust.sdk'),
                ('Localytics.framework', 'com.localytics.ios'),
            ):
                fw_dir = app_root / 'Frameworks' / fw_name
                fw_dir.mkdir(parents=True)
                (fw_dir / 'Info.plist').write_bytes(
                    plistlib.dumps({'CFBundleIdentifier': bid}))
            deps = get_embedded_framework_deps({'app_root': app_root})
            self.assertIn('com.appsflyer.AppsFlyerLib', deps)
            self.assertIn('FirebaseAnalytics', deps)
            with (mock.patch.object(Trackers, '_update_tracker_db'),
                  mock.patch(
                      'mobsf.MalwareAnalyzer.views.Trackers.append_scan_status',
            )):
                trk = Trackers('0' * 32, None, settings.TOOLS_DIR)
                res = trk.get_trackers_domains_or_deps([], deps)
            names = {t['name'] for t in res['trackers']}
            self.assertIn('AppsFlyer', names)
            self.assertIn('Google Firebase Analytics', names)
            self.assertIn('Adjust', names)
            self.assertIn('Localytics', names)


class OSUnzipHardeningTests(SimpleTestCase):
    """Tests for hardened os_unzip staging and central-directory mode stripping."""

    @staticmethod
    def _build_malformed_symlink_zip(
            zip_path, comment=b'', prepend=b'',
            pad_before_eocd=b'', corrupt_cd_size=False):
        import struct
        import zipfile
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zi = zipfile.ZipInfo('EvilLink.java')
            zi.external_attr = (0o120777 << 16)
            zi.create_system = 3
            zf.writestr(zi, '/etc/passwd')
            zf.writestr('Normal.java', 'class Normal {}')
            zf.comment = comment
        raw = bytearray(zip_path.read_bytes())
        eocd_pos = len(raw) - 22 - len(comment)
        if corrupt_cd_size:
            raw[eocd_pos + 12:eocd_pos + 16] = struct.pack('<I', 5)
        if pad_before_eocd:
            raw = raw[:eocd_pos] + bytearray(pad_before_eocd) + raw[eocd_pos:]
        if prepend:
            raw = bytearray(prepend) + raw
        zip_path.write_bytes(bytes(raw))

    def test_neutralize_handles_eocd_sig_in_comment_and_padding(self):
        import tempfile
        from mobsf.StaticAnalyzer.views.common.shared_func import (
            unzip,
        )
        from unittest import mock
        cases = (
            {'comment': b'pad' + b'PK\x05\x06', 'corrupt_cd_size': True},
            {'pad_before_eocd': b'XYZ'},
            {'prepend': b'JUNK' * 8, 'comment': b'trail' + b'PK\x05\x06'},
        )
        for kwargs in cases:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                zpath = tmp_path / 'malformed.zip'
                ext = tmp_path / 'ext'
                ext.mkdir()
                self._build_malformed_symlink_zip(zpath, **kwargs)
                with mock.patch(
                    'mobsf.StaticAnalyzer.views.common.shared_func.'
                    'append_scan_status',
                ):
                    unzip('0' * 32, zpath.as_posix(), ext.as_posix())
                self.assertTrue((ext / 'Normal.java').is_file())
                for item in ext.rglob('*'):
                    self.assertFalse(item.is_symlink())

    def test_os_unzip_staging_blocks_symlinks_even_if_unpatched(self):
        import shutil
        import tempfile
        import zipfile
        from unittest import mock
        from mobsf.StaticAnalyzer.views.common.shared_func import (
            os_unzip,
        )
        if not shutil.which('unzip'):
            self.skipTest('unzip binary not available')
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = tmp_path / 'unpatched.zip'
            unpatched_copy = tmp_path / 'unpatched_copy.zip'
            ext = tmp_path / 'ext'
            ext.mkdir()
            with zipfile.ZipFile(zpath, 'w') as zf:
                ext_link = zipfile.ZipInfo('ext_link.java')
                ext_link.external_attr = (0o120777 << 16)
                ext_link.create_system = 3
                zf.writestr(ext_link, '/etc/passwd')
                int_link = zipfile.ZipInfo('int_link.java')
                int_link.external_attr = (0o120777 << 16)
                int_link.create_system = 3
                zf.writestr(int_link, 'Safe.java')
                zf.writestr('Safe.java', 'class Safe {}')
            shutil.copyfile(zpath, unpatched_copy)
            # Simulate neutralize_zip_special_modes returning an unpatched zip
            with (mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.'
                'neutralize_zip_special_modes',
                return_value=unpatched_copy.as_posix(),
            ), mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.append_scan_status',
            )):
                os_unzip('0' * 32, zpath.as_posix(), ext.as_posix())
            self.assertTrue((ext / 'Safe.java').is_file())
            self.assertFalse((ext / 'ext_link.java').exists())
            self.assertFalse((ext / 'ext_link.java').is_symlink())
            self.assertFalse((ext / 'int_link.java').exists())
            self.assertFalse((ext / 'int_link.java').is_symlink())

    def test_os_unzip_fails_closed_when_neutralize_raises(self):
        import shutil
        import tempfile
        from unittest import mock
        from mobsf.StaticAnalyzer.views.common.shared_func import (
            os_unzip,
        )
        if not shutil.which('unzip'):
            self.skipTest('unzip binary not available')
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zpath = tmp_path / 'fail.zip'
            zpath.write_bytes(b'not a zip')
            ext = tmp_path / 'ext'
            ext.mkdir()
            with (mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.'
                'neutralize_zip_special_modes',
                side_effect=OSError('disk full'),
            ), mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.subprocess.call',
            ) as mock_call, mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.append_scan_status',
            )):
                res = os_unzip('0' * 32, zpath.as_posix(), ext.as_posix())
            self.assertEqual(res, [])
            mock_call.assert_not_called()

    def test_strings_and_entropies_skips_symlinks(self):
        import os
        import tempfile
        from unittest import mock
        from mobsf.StaticAnalyzer.views.common.shared_func import (
            strings_and_entropies,
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            secret_target = tmp_path / 'outside.txt'
            secret_target.write_text(
                'class Secret { String k = "super_secret_linked_value"; }')
            src = tmp_path / 'src'
            src.mkdir()
            (src / 'Real.java').write_text(
                'class Real { String s = "normal_code_string"; }')
            os.symlink(secret_target, src / 'Linked.java')
            with mock.patch(
                'mobsf.StaticAnalyzer.views.common.shared_func.append_scan_status',
            ):
                data = strings_and_entropies('0' * 32, src, ['.java'])
            self.assertIn('normal_code_string', data['strings'])
            self.assertNotIn('super_secret_linked_value', data['strings'])
