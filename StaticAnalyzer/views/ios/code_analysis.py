import re
import os
import io
import ntpath
import shutil
from django.utils.html import escape

from MalwareAnalyzer.views import MalwareCheck
from MobSF.utils import (
    PrintException,
)


def ios_source_analysis(src, md5_hash):
    """iOS Objective-C Code Analysis"""
    try:
        code_analysis_dict = {}
        print "[INFO] Starting iOS Source Code and PLIST Analysis"
        all_urls_list = []
        urls = []
        emails = []
        code_analysis_dict["html"] = ''
        code_analysis_dict["code_anal"] = ''
        code_analysis_dict["urlnfile"] = ''
        code_analysis_dict["emailnfile"] = ''
        code_analysis_dict["domains"] = {}
        findings = {key: [] for key in ('i_buf',
                                        'webv',
                                        'i_log',
                                        'net',
                                        'i_sqlite',
                                        'fileio',
                                        'ssl_bypass',
                                        'ssl_uiwebview',
                                        'path_traversal')}
        for dirname, _, files in os.walk(src):
            for jfile in files:
                if jfile.endswith(".m"):

                    jfile_path = os.path.join(src, dirname, jfile)
                    if "+" in jfile:
                        new_path = os.path.join(
                            src, dirname, jfile.replace("+", "x"))
                        shutil.move(jfile_path, new_path)
                        jfile_path = new_path
                    dat = ''
                    with io.open(jfile_path, mode='r', encoding="utf8", errors="ignore") as flip:
                        dat = flip.read()

                    # API
                    if re.findall(r"NSURL|CFStream|NSStream", dat):
                        findings['net'].append(jfile_path.replace(src, ''))
                    if (re.findall(r"Keychain|kSecAttrAccessibleWhenUnlocked|" +
                                   r"kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|" +
                                   r"SecItemUpdate|NSDataWritingFileProtectionComplete", dat)
                       ):
                        findings['fileio'].append(jfile_path.replace(src, ''))
                    if re.findall(r"WebView|UIWebView", dat):
                        findings['webv'].append(jfile_path.replace(src, ''))

                    # SECURITY ANALYSIS
                    if (re.findall(r"strcpy|memcpy|strcat|strncat|strncpy|sprintf|" +
                                   r"vsprintf|gets", dat)
                       ):
                        findings['i_buf'].append(jfile_path.replace(src, ''))
                    if re.findall(r"NSLog", dat):
                        findings['i_log'].append(jfile_path.replace(src, ''))
                    if re.findall(r"sqlite3_exec", dat):
                        findings['i_sqlite'].append(
                            jfile_path.replace(src, ''))
                    if re.findall(r'canAuthenticateAgainstProtectionSpace|' +
                                  r'continueWithoutCredentialForAuthenticationChallenge|' +
                                  r'kCFStreamSSLAllowsExpiredCertificates|' +
                                  r'kCFStreamSSLAllowsAnyRoot|' +
                                  r'kCFStreamSSLAllowsExpiredRoots|' +
                                  r'allowInvalidCertificates\s*=\s*(YES|yes)', dat):
                        findings['ssl_bypass'].append(
                            jfile_path.replace(src, ''))
                    if re.findall(r'setAllowsAnyHTTPSCertificate:\s*YES|'+
                                  r'allowsAnyHTTPSCertificateForHost|'+
                                  r'loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)', dat):
                        findings['ssl_uiwebview'].append(
                            jfile_path.replace(src, ''))
                    if "NSTemporaryDirectory()," in dat:
                        findings['path_traversal'].append(
                            jfile_path.replace(src, ''))

                    relative_fpath = jfile_path.replace(src, '')
                    base_fl = ntpath.basename(relative_fpath)
                    # URLs My Custom regex
                    url_regex = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|'+
                                           ur'data:|www\d{0,3}[.])[\w().=/;,#:'+
                                           ur'@?&~*+!$%\'{}-]+)', re.UNICODE)
                    urllist = re.findall(url_regex, dat.lower())
                    all_urls_list.extend(urllist)
                    uflag = 0
                    for url in urllist:
                        if url not in urls:
                            urls.append(url)
                            uflag = 1
                    if uflag == 1:
                        code_analysis_dict["urlnfile"] += "<tr><td>" + "<br>".join(urls) + \
                            "</td><td><a href='../ViewFile/?file=" + escape(relative_fpath) + \
                            "&type=m&mode=ios&md5=" + md5_hash + "'>" + escape(base_fl) + \
                            "</a></td></tr>"
                    # Email Etraction Regex

                    regex = re.compile(r"[\w.-]+@[\w-]+\.[\w.]+")
                    eflag = 0
                    for email in regex.findall(dat.lower()):
                        if (email not in emails) and (not email.startswith('//')):
                            emails.append(email)
                            eflag = 1
                    if eflag == 1:
                        code_analysis_dict["emailnfile"] += "<tr><td>" + "<br>".join(emails) + \
                            "</td><td><a href='../ViewFile/?file=" +\
                            escape(relative_fpath) + "&type=m&mode=ios&md5=" + md5_hash +\
                            "'>" + escape(base_fl) + "</a></td></tr>"
        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        code_analysis_dict["domains"] = MalwareCheck(all_urls_list)
        print "[INFO] Finished Code Analysis, Email and URL Extraction"

        api_mappings = {'webv': 'WebView Component',
                        'net': 'Network Calls',
                        'fileio': 'Local File I/O Operations.',
                       }
        html = ''
        for key_tag in api_mappings:
            if findings[key_tag]:
                link = ''
                item = "<tr><td>" + api_mappings[key_tag] + "</td><td>"
                for ktag in findings[key_tag]:
                    link += "<a href='../ViewFile/?file=" + \
                        escape(ktag) + "&type=m&mode=ios&md5=" + md5_hash + \
                        "'>" + escape(ntpath.basename(ktag)) + "</a> "
                html += item + link + "</td></tr>"
        sec_desc_mappings = {'i_buf': 'The App may contain banned API(s). These API(s)' +
                                      ' are insecure and must not be used.',
                             'i_log': 'The App logs information. Sensitive information ' +
                                      'should never be logged.',
                             'i_sqlite': 'App uses SQLite Database. ' +
                                         'Sensitive Information should be encrypted.',
                             'ssl_bypass': 'App allows self signed or invalid ' +
                                           'SSL certificates. App is vulnerable to MITM attacks.',
                             'ssl_uiwebview': 'UIWebView in App ignore SSL errors and accept' +
                                              ' any SSL Certificate. App is vulnerable '+
                                              'to MITM attacks.',
                             'path_traversal': 'Untrusted user input to "NSTemporaryDirectory()"' +
                                               ' will result in path traversal vulnerability.',
                            }
        spn_dang = '<span class="label label-danger">high</span>'
        spn_info = '<span class="label label-info">info</span>'
        spn_sec = '<span class="label label-success">secure</span>'
        spn_warn = '<span class="label label-warning">warning</span>'
        for k in sec_desc_mappings:
            if findings[k]:
                link = ''
                if re.findall('i_sqlite', k):
                    item = '<tr><td>' + sec_desc_mappings[k] + \
                        '</td><td>' + spn_info + '</td><td>'
                elif re.findall('path_traversal', k):
                    item = '<tr><td>' + sec_desc_mappings[k] + \
                        '</td><td>' + spn_warn + '</td><td>'
                else:
                    item = '<tr><td>' + sec_desc_mappings[k] + \
                        '</td><td>' + spn_dang + '</td><td>'
                for filname in findings[k]:
                    link += "<a href='../ViewFile/?file=" + \
                        escape(filname) + "&type=m&mode=ios&md5=" + md5_hash + \
                        "'>" + escape(ntpath.basename(filname)) + "</a> "

                code_analysis_dict["code_anal"] += item + link + "</td></tr>"
        code_analysis_dict["html"] = html
        return code_analysis_dict
    except:
        PrintException("[ERROR] iOS Source Code Analysis")
