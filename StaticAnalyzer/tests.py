#!/usr/bin/env python
import json
import logging
import os
import platform

from django.conf import settings
from django.http import HttpResponse
from django.test import Client, TestCase

from MobSF.utils import api_key

logger = logging.getLogger(__name__)

RESCAN = False
# Set RESCAN to True if Static Analyzer Code is modified


def static_analysis_test():
    """Test Static Analyzer."""
    logger.info('Running Static Analyzer Unit test')
    try:
        uploaded = []
        logger.info('Running Upload Test')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            fpath = os.path.join(apk_dir, filename)
            with open(fpath, 'rb') as filp:
                response = http_client.post('/upload/', {'file': filp})
                obj = json.loads(response.content.decode('utf-8'))
                if response.status_code == 200 and obj['status'] == 'success':
                    logger.info('[OK] Upload OK: %s', filename)
                    uploaded.append(obj['url'])
                else:
                    logger.error('Performing Upload: %s', filename)
                    return True
        logger.info('[OK] Completed Upload test')
        logger.info('Running Static Analysis Test')
        for upl in uploaded:
            if RESCAN:
                upl = '/' + upl + '&rescan=1'
            else:
                upl = '/' + upl
            resp = http_client.get(upl, follow=True)
            if resp.status_code == 200:
                logger.info('[OK] Static Analysis Complete: %s', upl)
            else:
                logger.error('Performing Static Analysis: %s', upl)
                return True
        logger.info('[OK] Static Analysis test completed')
        logger.info('Running PDF Generation Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                '/PDF/?md5=3a552566097a8de588b8184b059b0158&type=APK',
                '/PDF/?md5=6c23c2970551be15f32bbab0b5db0c71&type=IPA',
                '/PDF/?md5=52c50ae824e329ba8b5b7a0f523efffe&type=ANDZIP',
                '/PDF/?md5=57bb5be0ea44a755ada4a93885c3825e&type=IOSZIP',
                '/PDF/?md5=8179b557433835827a70510584f3143e&type=APPX',
            ]
        else:
            pdfs = [
                '/PDF/?md5=3a552566097a8de588b8184b059b0158&type=APK',
                '/PDF/?md5=52c50ae824e329ba8b5b7a0f523efffe&type=ANDZIP',
                '/PDF/?md5=57bb5be0ea44a755ada4a93885c3825e&type=IOSZIP',
                '/PDF/?md5=8179b557433835827a70510584f3143e&type=APPX',
            ]

        for pdf in pdfs:
            resp = http_client.get(pdf)
            if (resp.status_code == 200
                    and resp._headers['content-type'][1] == 'application/pdf'):
                logger.info('[OK] PDF Report Generated: %s', pdf)
            else:
                logger.error('Generating PDF: %s', pdf)
                logger.info(resp.content)
                return True
        logger.info('[OK] PDF Generation test completed')

        # Compare apps test
        logger.info('Running App Compare tests')
        first_app = '3a552566097a8de588b8184b059b0158'
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
        logger.info('Running Delete Scan Results test')
        # Deleting Scan Results
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['3a552566097a8de588b8184b059b0158',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e']
        else:
            scan_md5s = ['3a552566097a8de588b8184b059b0158',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e']
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
    return False


def api_test():
    """View for Handling REST API Test."""
    logger.info('\nRunning REST API Unit test')
    auth = api_key()
    try:
        uploaded = []
        logger.info('Running Test on Upload API')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            fpath = os.path.join(apk_dir, filename)
            if (platform.system() not in ['Darwin', 'Linux']
                    and fpath.endswith('.ipa')):
                continue
            with open(fpath, 'rb') as filp:
                response = http_client.post(
                    '/api/v1/upload', {'file': filp}, HTTP_AUTHORIZATION=auth)
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
                '/api/v1/scan', upl, HTTP_AUTHORIZATION=auth)
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
        logger.info('[OK] Scan List API tests completed')
        # PDF Tests
        logger.info('Running PDF Generation API Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                {'hash': '3a552566097a8de588b8184b059b0158',
                 'scan_type': 'apk'},
                {'hash': '6c23c2970551be15f32bbab0b5db0c71',
                 'scan_type': 'ipa'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe',
                 'scan_type': 'andzip'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e',
                 'scan_type': 'ioszip'},
                {'hash': '8179b557433835827a70510584f3143e',
                 'scan_type': 'appx'},
            ]
        else:
            pdfs = [
                {'hash': '3a552566097a8de588b8184b059b0158',
                 'scan_type': 'apk'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe',
                 'scan_type': 'andzip'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e',
                 'scan_type': 'ioszip'},
                {'hash': '8179b557433835827a70510584f3143e',
                 'scan_type': 'appx'},
            ]
        for pdf in pdfs:
            resp = http_client.post(
                '/api/v1/download_pdf', pdf, HTTP_AUTHORIZATION=auth)
            if (resp.status_code == 200
                    and resp._headers['content-type'][1] == 'application/pdf'):
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
            if (resp.status_code == 200
                    and resp._headers['content-type'][1] == ctype):
                logger.info('[OK] JSON Report Generated: %s', jsn['hash'])
            else:
                logger.error('Generating JSON Response: %s', jsn['hash'])
                return True
        logger.info('[OK] JSON Report API test completed')
        logger.info('Running View Source API test')
        # View Source tests
        files = [{'file': 'opensecurity/helloworld/MainActivity.java',
                  'type': 'apk',
                  'hash': '3a552566097a8de588b8184b059b0158'},
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
        logger.info('Running Delete Scan API Results test')
        # Deleting Scan Results
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['3a552566097a8de588b8184b059b0158',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         ]
        else:
            scan_md5s = ['3a552566097a8de588b8184b059b0158',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
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
