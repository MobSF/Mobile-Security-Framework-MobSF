#!/usr/bin/env python
import os
import platform
import json

from django.conf import settings
from django.test import Client
from django.http import HttpResponse

from MobSF.utils import PrintException

RESCAN = False
# Set RESCAN to True if Static Analyzer Code is modified


def static_analysis():
    """Test Static Analyzer"""
    failed = False
    err_msg = '%s'
    if platform.system() != "Windows":
        err_msg = '\033[91m \033[1m %s \033[0m'
    try:
        uploaded = []
        print "[INFO] Running Upload Test"
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, "StaticAnalyzer/test_files/")
        for filename in os.listdir(apk_dir):
            fpath = os.path.join(apk_dir, filename)
            with open(fpath) as filp:
                response = http_client.post('/upload/', {'file': filp})
                obj = json.loads(response.content)
                if response.status_code == 200 and obj["status"] == "success":
                    print "[OK] Upload OK: " + filename
                    uploaded.append(obj["url"])
                else:
                    print err_msg % "[ERROR] Performing Upload" + filename
                    failed = True
        print "[OK] Completed Upload test"
        print "[INFO] Running Static Analysis Test"
        for upl in uploaded:
            if RESCAN:
                upl = "/" + upl + "&rescan=1"
            else:
                upl = "/" + upl
            resp = http_client.get(upl, follow=True)
            if resp.status_code == 200:
                print "[OK] Static Analysis Complete: " + upl
            else:
                print err_msg % "[ERROR] Performing Static Analysis: " + upl
                failed = True
        print "[OK] Static Analysis test completed"
        print "[INFO] Running PDF Generation Test"

        pdfs = [
            "/PDF/?md5=3a552566097a8de588b8184b059b0158&type=APK",
            "/PDF/?md5=6c23c2970551be15f32bbab0b5db0c71&type=IPA",
            "/PDF/?md5=52c50ae824e329ba8b5b7a0f523efffe&type=ANDZIP",
            "/PDF/?md5=57bb5be0ea44a755ada4a93885c3825e&type=IOSZIP",
            "/PDF/?md5=8179b557433835827a70510584f3143e&type=APPX",
        ]
        for pdf in pdfs:
            resp = http_client.get(pdf)
            if (resp.status_code == 200 and
                    resp._headers['content-type'][1] == "application/pdf"
                    ):
                print "[OK] PDF Report Generated: " + pdf
            else:
                print err_msg % "[ERROR] Generating PDF: " + pdf
                print resp.content
                failed = True
        print "[OK] PDF Generation test completed"
        print "[INFO] Running Delete Scan Results test"
        # Deleting Scan Results
        scan_md5s = ["3a552566097a8de588b8184b059b0158", "6c23c2970551be15f32bbab0b5db0c71",
                     "52c50ae824e329ba8b5b7a0f523efffe", "57bb5be0ea44a755ada4a93885c3825e", "8179b557433835827a70510584f3143e"]
        for md5 in scan_md5s:
            resp = http_client.post('/delete_scan/', {'md5': md5})
            if resp.status_code == 200:
                dat = json.loads(resp.content)
                if dat["deleted"] == "yes":
                    print "[OK] Deleted Scan: " + md5
                else:
                    print err_msg % "[ERROR] Deleting Scan: " + md5
                    failed = True
            else:
                print err_msg % "[ERROR] Deleting Scan: " + md5
                failed = True
        print "[INFO] Delete Scan Results test completed"
    except:
        PrintException("[ERROR] Completing Static Analyzer Test")
    return failed


def start_test(request):
    """View for Handling Test"""
    print "\n[INFO] Running Static Analyzer Unit test"
    try:
        failed_status = static_analysis()
        if failed_status:
            message = "some tests failed"
        else:
            message = "all tests completed"
    except:
        message = "error"
    print "\n\n[INFO] ALL TESTS COMPLETED!"
    print "[INFO] Test Status: " + message
    return HttpResponse(json.dumps({"static_analyzer_test": message}),
                        content_type="application/json")
