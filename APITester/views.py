# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from random import randint,shuffle,choice
from urlparse import urlparse
from cgi import parse_qs
from APITester.models import ScopeURLSandTests
from MobSF.exception_printer import PrintException
from django.template.defaulttags import register
from django.template.defaultfilters import stringfilter
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe
import tornado.httpclient
import os,re,json,io,hashlib,datetime,socket,string
from lxml import etree

@register.filter
def key(d, key_name):
    return d[key_name]

@register.filter
def spacify(value, autoescape=None):
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x
    return mark_safe(re.sub('\s', '&'+'nbsp;', esc(value)))
spacify.needs_autoescape = True


TESTS = ['Information Gathering','Security Headers','Insecure Direct Object Reference','Session Handling','SSRF','XXE','Path Traversal','Rate Limit Check']
STATUS = { "INFO": "<span class='label label-info'>Info</span>", "SECURE": "<span class='label label-success'>Secure</span>", "INSECURE": "<span class='label label-danger'>Insecure</span>", "WARNING": "<span class='label label-warning'>Warning</span>"}

def APITester(request):
    #Bug show login, logout, register etc if session is selected
    global TESTS
    print "\n[INFO] API Testing Started"
    try:
        if request.method == 'GET':
            MD5=request.GET['md5']
            m=re.match('[0-9a-f]{32}',MD5)
            if m:
                URLS = getListOfURLS(MD5,False)
                context = {'title' : 'API Tester',
                    'urlmsg': 'Select URLs under Scope',
                    'md5' : MD5,
                    'urls' : URLS,
                    'tstmsg': 'Select Tests',
                    'tests': TESTS,
                    'btntxt': 'Next',
                    'formloc': '../APITester/',
                    'd':'',
                    'v':'display: none;',
                    'dict_urls': {},
                    }
                template="api_tester.html"
                return render(request,template,context)
            else:
                return HttpResponseRedirect('/error/')
        elif request.method =="POST":
            MD5=request.POST['md5']
            m=re.match('[0-9a-f]{32}',MD5)
            if m:
                SCOPE_URLS = [] #All DOMAINS that needs to be tested
                SCOPE_TESTS = [] #All TESTS that needs to be executed
                DICT_URLS = {} # {domain:{url1,url2}, domain2:{url1,url2,url3}}

                SCOPE=request.POST.getlist('scope')
                SELECTED_TESTS=request.POST.getlist('tests')

                URLS = getListOfURLS(MD5,False)

                for s in SCOPE:
                    SCOPE_URLS.append(URLS[int(s)])
                for t in SELECTED_TESTS:
                    SCOPE_TESTS.append(TESTS[int(t)])

                #Save Scope URLs and Tests to DB
                DB=ScopeURLSandTests.objects.filter(MD5=MD5)
                if not DB.exists():
                    ScopeURLSandTests(MD5=MD5,SCOPEURLS=SCOPE_URLS,SCOPETESTS=SCOPE_TESTS).save()
                else:
                    ScopeURLSandTests.objects.filter(MD5=MD5).update(MD5=MD5,SCOPEURLS=SCOPE_URLS,SCOPETESTS=SCOPE_TESTS)

                allurls = getListOfURLS(MD5,True)
                for url in allurls:
                    if getProtocolDomain(url) in SCOPE_URLS:
                        if getProtocolDomain(url) in DICT_URLS:
                            DICT_URLS[getProtocolDomain(url)].append(url)
                        else:
                            DICT_URLS[getProtocolDomain(url)] = [url]
                context = {'title' : 'API Tester',
                    'urlmsg': 'Selected URLs',
                    'md5' : MD5,
                    'urls' : SCOPE_URLS,
                    'tstmsg': 'Selected Tests',
                    'tests': SCOPE_TESTS,
                    'btntxt': 'Start Scan',
                    'formloc': '../StartScan/',
                    'd': 'disabled',
                    'v': '',
                    'dict_urls': DICT_URLS,

                    }
                template="api_tester.html"
                return render(request,template,context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] APITester")
        return HttpResponseRedirect('/error/')
def StartScan(request):
    print "\n[INFO] Web API Scan Started"
    try:
        if request.method =="POST":
            MD5=request.POST['md5']
            m=re.match('[0-9a-f]{32}',MD5)
            if m:
                #Scan Mode
                SCAN_MODE=request.POST['scanmode']
                URLS_CONF = {}
                #Untrusted User Input
                for key, value in request.POST.iteritems():
                    if key.startswith("login-") or key.startswith("pin-") or key.startswith("logout-") or key.startswith("register-"):
                        action_domain = key.split("-",1)
                        #[action,url]
                        if action_domain[1] in URLS_CONF:
                            URLS_CONF[action_domain[1]][action_domain[0]] = value
                        else:
                            URLS_CONF[action_domain[1]] = {action_domain[0]:value}

                print URLS_CONF

                RESULT = {}
                SCOPE_URLS = []
                SELECTED_TESTS = []
                DB=ScopeURLSandTests.objects.filter(MD5=MD5)
                if DB.exists():
                    SCOPE_URLS = DB[0].SCOPEURLS
                    SELECTED_TESTS = DB[0].SCOPETESTS

                SCAN_REQUESTS, LOGOUT_REQUESTS = getScanRequests(MD5,SCOPE_URLS,URLS_CONF) #List of Request Dict that we need to scan
                if 'Information Gathering' in SELECTED_TESTS:
                    res = api_info_gathering(SCOPE_URLS)
                    if res:
                        RESULT['Information Gathering'] = res
                    #Format : [{techinfo:foo, url:foo, proof:foo, request:foo, response:foo},..]
                if 'Security Headers' in SELECTED_TESTS:
                    res = api_security_headers(SCOPE_URLS)
                    if res:
                        RESULT['Security Headers'] = res
                if 'SSRF' in SELECTED_TESTS:
                    res = api_ssrf(SCAN_REQUESTS)
                    if res:
                        RESULT['SSRF'] = res
                if 'XXE' in SELECTED_TESTS:
                    res = api_xxe(SCAN_REQUESTS)
                    if res:
                        RESULT['XXE'] = res
                if 'Path Traversal' in SELECTED_TESTS:
                    res = api_pathtraversal(SCAN_REQUESTS, SCAN_MODE)
                    if res:
                        RESULT['Path Traversal'] = res
                if 'Rate Limit Check' in SELECTED_TESTS:
                    res = api_check_ratelimit(SCAN_REQUESTS,URLS_CONF)
                    if res:
                        RESULT['Rate Limit Check'] = res
                
                #Format : RESULT {"Information Gathering":[{}, {}, {}, {}], "blaa": [{}, {}, {}, {}]}
                context = {'result': RESULT,
                'title':'Web API Scan Results'}
                template="web_api_scan.html"
                return render(request,template,context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Web API Scan")
        return HttpResponseRedirect('/error/')
#==============
#Security Scan
#==============

#INFORMATION GATHERING

def api_info_gathering(SCOPE_URLS):
    global STATUS
    print "\n[INFO] Performing Information Gathering"
    result = []
    try:
        #Initally Do on Scope URLs
        for url in SCOPE_URLS:
            response = HTTP_GET_Request(url)
            if not response == None:
                for header, value in list(response.headers.items()):
                    if header.lower() == "server":
                        result.append(genFindingsDict(STATUS["INFO"]+" Server Information Disclosure", url, header + ": " +value, response))
                    elif header.lower() == "x-powered-by":
                        result.append(genFindingsDict(STATUS["INFO"]+" Technology Information Disclosure",url,header + ": " +value,response))
                    elif header.lower() == "x-aspnetmvc-version":
                        result.append(genFindingsDict(STATUS["INFO"]+" ASP.NET MVC Version Disclosure",url,header + ": " +value,response))
                    elif header.lower() == "x-aspnet-version":
                        result.append(genFindingsDict(STATUS["INFO"]+" ASP.NET Version Disclosure",url,header + ": " +value,response))

        '''
        do on all request objects captured if it's not found on parent domain
        really needed?
        when execptions triggers, some times server info is discliosed
        for req in SCAN_REQUESTS:
            response=HTTP_Request(req)
        '''
    except:
        PrintException("[ERROR] Information Gathering Module")
    return result

#SECURITY HEADERS

def api_security_headers(SCOPE_URLS):
    global STATUS
    result = []
    print "\n[INFO] Checking for Security Headers"
    try:

        #Initally Do on Scope URLs
        for url in SCOPE_URLS:
            response = HTTP_GET_Request(url)
            if not response == None:
                XSS_PROTECTION = False
                HSTS_PROTECTION = False
                HPKP_PROTECTION = False
                XFRAME_PROTECTION = False
                CONTENTSNIFF_PROTECTION =False
                CSP_PROTECTION = False
                for header, value in list(response.headers.items()):

                    if header.lower() == "x-xss-protection":
                        XSS_PROTECTION = True
                        if re.findall("(\s)*1(\s)*(;)*(\s)*(mode=block)*",value.lower()):
                            result.append(genFindingsDict(STATUS["SECURE"] + " X-XSS Protection Header is properly set. This enables browsers Anti-XSS Filters. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        elif re.findall("(\s)*0(\s)*",value.lower()):
                            result.append(genFindingsDict(STATUS["INSECURE"]  + " X-XSS Protection Header is set to 0. This will disable browsers Anti-XSS Filters. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        else:
                            result.append(genFindingsDict(STATUS["WARNING"] + " X-XSS Protection Header might be configured incorrectly. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                    elif header.lower() == "strict-transport-security":
                        if url.startswith("https://"):
                            HSTS_PROTECTION = True
                            result.append(genFindingsDict(STATUS["SECURE"] + " Strict Transport Security header is present. This header ensure that all the networking calls made form the browser are strictly (https). (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        else:
                            HSTS_PROTECTION = True #Not Applicable for http URLs
                    elif header.lower() == "public-key-pins":
                        if url.startswith("https://"):
                            HPKP_PROTECTION  = True
                            result.append(genFindingsDict(STATUS["SECURE"] + " Public Key Pinning header is present. This header tells the browser to perform certificate pinning. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        else:
                            HPKP_PROTECTION  = True #Not Applicable for http URLs
                    elif header.lower() == "x-frame-options":
                        XFRAME_PROTECTION = True
                        if re.findall("(\s)*deny|sameorigin(\s)*",value.lower()):
                            result.append(genFindingsDict(STATUS["SECURE"] + " X-Frame-Options Header is properly set. This header restrict other websites from creating IFRAME(s) of this domain. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        elif re.findall("(\s)*allow-from(\s)*",value.lower()):
                            result.append(genFindingsDict(STATUS["INFO"] + " X-Frame-Options Header is set. This header allows only whitelisted domain to create IFRAME(s) of this domain. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        else:
                            result.append(genFindingsDict(STATUS["WARNING"] + " X-Frame-Options Header might be configured incorrectly. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                    elif header.lower() == "x-content-type-options":
                        CONTENTSNIFF_PROTECTION = True
                        if re.findall("(\s)*nosniff(\s)*",value.lower()):
                            result.append(genFindingsDict(STATUS["SECURE"] + " X-Content-Type-Options Header is present. This header prevents browser from MIME-sniffing a response away from the declared content-type. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                        else:
                            result.append(genFindingsDict(STATUS["WARNING"] + " X-Content-Type-Options Header might be configured incorrectly. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))

                    elif header.lower() == "content-security-policy":
                        CSP_PROTECTION = True
                        result.append(genFindingsDict(STATUS["SECURE"] + " Content-Security-Policy Header is present. This header enables extra security features of the browser and prevents browser based client side attacks. Please verify the policy manually. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))
                    elif header.lower() == "content-security-policy-report-only":
                        CSP_PROTECTION == True
                        result.append(genFindingsDict(STATUS["INFO"] + " Content-Security-Policy Header is present in Report only mode. (Not Applicable for Mobile APIs)",url,header + ": " +value,response))


                if XSS_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " X-XSS Protection Header is not present. (Not Applicable for Mobile APIs)",url,"X-XSS-Protection Header not present",response))
                if HSTS_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " Strict Transport Security Header is not present. This header ensure that all the networking calls made form the browser are strictly (https). (Not Applicable for Mobile APIs)",url,"Strict-Transport-Security Header not present",response))
                if HSTS_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " Public Key Pinning Header is not present. This header tells the browser to perform certificate pinning. (Not Applicable for Mobile APIs)",url,"Public-Key-Pins Header not present",response))
                if XFRAME_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " X-Frame-Options Header is not present. This header restrict other websites from creating IFRAME(s) of this domain. (Not Applicable for Mobile APIs)",url,"X-Frame-Options Header not present",response))
                if CONTENTSNIFF_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " X-Content-Type-Options Header is not present. This header prevents browser from MIME-sniffing a response away from the declared content-type. (Not Applicable for Mobile APIs)",url,"X-Content-Type-Options Header not present",response))
                if CSP_PROTECTION == False:
                    result.append(genFindingsDict(STATUS["WARNING"] + " Content-Security-Policy Header is not present. This header enables extra security features of the browser and prevents browser based client side attacks. (Not Applicable for Mobile APIs)",url,"Content-Security-Policy Header not present",response))
    except:
        PrintException("[ERROR] Checking for Security Headers")
    return result

#SSRF

def api_ssrf(SCAN_REQUESTS):
    '''
    This module scans for SSRF in request uri and body and confirms the vulnerability using MobSF Cloud Server.
    '''
    global STATUS
    result = []
    SSRF_MSG_1 =" Server Side Request Forgery (SSRF) is identified in Request URI"
    SSRF_MSG_2 =" Server Side Request Forgery (SSRF) is identified in Request Body"

    print "\n[INFO] Starting SSRF Tester"
    try:
        for request in SCAN_REQUESTS:

            url = request["url"]
            domain = getProtocolDomain(url)
            path_n_querystring = url.replace(domain,"")


            #SSRF Test on URI
            if len(path_n_querystring) > 0:
                SSRF_entry_list = extractURLS(path_n_querystring)
                if len(SSRF_entry_list) > 0:
                    print "\n[INFO] Injecting SSRF Payload on URI"
                    request_uri = request
                    #for each URL in path + querystring
                    for entry in SSRF_entry_list:
                        #Inject payload and test (one at a time).
                        ip_check = True

                        #HASH METHOD
                        SSRF_MD5 = getMD5(str(datetime.datetime.now()) + str(randint(0,50000)))
                        if entry[0].isdigit():
                            #entry like 192.168.0.1:800
                            if settings.CLOUD_SERVER.startswith("http://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("http://","") + "/" + SSRF_MD5
                            elif settings.CLOUD_SERVER.startswith("https://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("https://","") + "/" + SSRF_MD5
                        else:
                            SSRF_PAYLOAD = settings.CLOUD_SERVER + "/"+ SSRF_MD5
                        new_pq = path_n_querystring.replace(entry,SSRF_PAYLOAD)
                        request_uri["url"] = domain + new_pq
                        ssrf_res = HTTP_Request(request_uri)
                        ssrf_res = HTTP_Request(request_uri)
                        if getStatusByHash(SSRF_MD5) == "yes":
                            ip_check = False
                            #SSRF detected
                            result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_1, url, "MobSF Cloud Server Detected SSRF via Hash Method", ssrf_res))
                        
                        #IP METHOD or REQUEST COUNT METHOD
                        if entry[0].isdigit():
                            if settings.CLOUD_SERVER.startswith("http://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("http://","")
                            elif settings.CLOUD_SERVER.startswith("https://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("https://","")
                        else:
                            SSRF_PAYLOAD = settings.CLOUD_SERVER
                        new_pq = path_n_querystring.replace(entry,SSRF_PAYLOAD)
                        request_uri["url"] = domain + new_pq
                        if ip_check:
                            #IP METHOD
                            #Check only if SSRF is not detected by Hash Method
                            ssrf_res = HTTP_Request(request_uri)
                            ssrf_res = HTTP_Request(request_uri)
                            if getStatusByIP(domain) == "yes":
                                #SSRF detected
                                result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_1, url, "MobSF Cloud Server Detected SSRF via IP Method", ssrf_res))
                            else:
                                #REQUEST COUNT METHOD
                                n_request = 5
                                for x in range(n_request):
                                    ssrf_res = HTTP_Request(request_uri)
                                if getStatusByCount(n_request) == "yes":
                                    #SSRF detected
                                    result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_1, url, "MobSF Cloud Server Detected SSRF via Request Count Method", ssrf_res))

            #SSRF Test on Request BODY
            if request["body"]:
                body = request["body"]
                SSRF_entry_list_body = extractURLS(body)
                if len(SSRF_entry_list_body) > 0:
                    request_bd = request
                    print "\n[INFO] Injecting SSRF Payload on Request Body"
                    #for each URL in request body
                    for entry in SSRF_entry_list_body:
                        #Inject payload and test (one at a time).
                        ip_check = True
                        
                        #HASH METHOD
                        SSRF_MD5 = getMD5(str(datetime.datetime.now()) + str(randint(0,50000)))
                        if entry[0].isdigit():
                            if settings.CLOUD_SERVER.startswith("http://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("http://","") + "/" + SSRF_MD5
                            elif settings.CLOUD_SERVER.startswith("https://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("https://","") + "/" + SSRF_MD5
                        else:
                            SSRF_PAYLOAD = settings.CLOUD_SERVER + "/"+ SSRF_MD5
                        request_bd["body"] = body.replace(entry,SSRF_PAYLOAD)
                        ssrf_res = HTTP_Request(request_bd)
                        ssrf_res = HTTP_Request(request_bd)
                        if getStatusByHash(SSRF_MD5) == "yes":
                            ip_check = False
                            #SSRF detected
                            result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_2, url, "MobSF Cloud Server Detected SSRF via Hash Method", ssrf_res))
                        
                        #IP METHOD or REQUEST COUNT METHOD
                        if entry[0].isdigit():
                            if settings.CLOUD_SERVER.startswith("http://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("http://","")
                            elif settings.CLOUD_SERVER.startswith("https://"):
                                SSRF_PAYLOAD = settings.CLOUD_SERVER.replace("https://","")
                        else:
                            SSRF_PAYLOAD = settings.CLOUD_SERVER
                        request_bd["body"] = body.replace(entry,SSRF_PAYLOAD)
                        if ip_check:
                            #IP METHOD
                            #Check only if SSRF is not detected by Hash Method
                            ssrf_res = HTTP_Request(request_bd)
                            ssrf_res = HTTP_Request(request_bd)
                            if getStatusByIP(domain) == "yes":
                                #SSRF detected
                                result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_2, url, "MobSF Cloud Server Detected SSRF via IP Method", ssrf_res))
                            else:
                                #REQUEST COUNT METHOD
                                n_request = 5
                                for x in range(n_request):
                                    ssrf_res = HTTP_Request(request_bd)
                                if getStatusByCount(n_request) == "yes":
                                    #SSRF detected
                                    result.append(genFindingsDict(STATUS["INSECURE"]+SSRF_MSG_2, url, "MobSF Cloud Server Detected SSRF via Request Count Method", ssrf_res))
    except:
        PrintException("[ERROR] SSRF Tester")
    return result

#XXE

def api_xxe(SCAN_REQUESTS):
    global STATUS
    result = []
    print "\n[INFO] Starting XXE Tester"
    try:
        for request in SCAN_REQUESTS:
            if request["body"]:
                url = request["url"]
                xml = False
                try:
                    config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
                    #Prevent Entity Expansion Attacks against the Framework
                    etree.fromstring(request["body"],config)
                    xml = True
                except:
                    xml = False
                    pass
                if xml:
                    #Start XXE Test
                    xxe_request = request
                    for xxe in xxe_paylods():
                        #append payload to body
                        XXE_MD5 = getMD5(str(datetime.datetime.now()) + str(randint(0,50000)))
                        XXE_PAYLOAD_URL = settings.CLOUD_SERVER + "/"+ XXE_MD5
                        XXE_PAYLOAD = xxe.replace("[CLOUD_SERVER_URL]",XXE_PAYLOAD_URL)
                        xxe_request["body"] = request["body"] + XXE_PAYLOAD
                        xxe_res = HTTP_Request(xxe_request)
                        xxe_res = HTTP_Request(xxe_request)
                        if getStatusByHash(XXE_MD5) == "yes":
                            #XXE detected
                            result.append(genFindingsDict(STATUS["INSECURE"]+"XML External Entity (XXE) Vulnerability Identified", url, "MobSF Cloud Server Detected XXE via Hash Method", xxe_res))
                            break
                        #replace body with payload
                        XXE_MD5 = getMD5(str(datetime.datetime.now()) + str(randint(0,50000)))
                        XXE_PAYLOAD_URL = settings.CLOUD_SERVER + "/"+ XXE_MD5
                        XXE_PAYLOAD = xxe.replace("[CLOUD_SERVER_URL]",XXE_PAYLOAD_URL)
                        xxe_request["body"] = XXE_PAYLOAD
                        xxe_res = HTTP_Request(xxe_request)
                        xxe_res = HTTP_Request(xxe_request)
                        if getStatusByHash(XXE_MD5) == "yes":
                            #XXE detected
                            result.append(genFindingsDict(STATUS["INSECURE"]+"XML External Entity (XXE) Vulnerability Identified", url, "MobSF Cloud Server Detected XXE via Hash Method", xxe_res))
                            break
    except:
        PrintException("[ERROR] XXE Tester")
    return result

#Path Traversal

def api_pathtraversal(SCAN_REQUESTS,SCAN_MODE):
    global STATUS
    result = []
    print "\n[INFO] Starting Path Traversal Tester"
    '''
    Perform path Traversal checks on Request URI and Body
    In URI only if it contains a parameter value a foooo.bar (filename.extl) or foo/bar/ddd ("/")
    '''
    try:
        for request in SCAN_REQUESTS:
            url = request["url"]

            #Scan in Request URI
            scan_val = []
            request_uri = request
            qs = urlparse(url).query
            prev_url = url.replace(qs,"")
            dict_qs = parse_qs(qs)
            #{key1: [val1], key2:[val1,val2]}
            for key in dict_qs:
                for val in dict_qs[key]:
                    if (is_number(val) == False) and ("/" in val):
                        scan_val.append(val)
                    if (is_number(val) == False) and (re.findall("^[\w]+[\W]*[\w]*[.][\w]{1,4}$",val)):
                        #not a number and matches a filename with extension
                        if re.findall("%40|@",val):
                            #we don't want to test email fields
                            pass
                        else:
                            scan_val.append(val)
            for val in scan_val:
                for payload in path_traversal_payloads(SCAN_MODE):
                    payload = payload.replace("{FILE}",settings.CHECK_FILE)
                    #print "\n\nURI"
                    #print "value is :", val
                    #print "replacing with ", payload
                    #print "new qs ", qs.replace(val,payload)
                    #print "old request uri", request_uri["url"]
                    request_uri["url"] = prev_url + qs.replace(val,payload)
                    #print "new request uri", request_uri["url"]
                    pt_res = HTTP_Request(request_uri)
                    if pt_res:
                        if (re.findall(settings.RESPONSE_REGEX,pt_res.body)):
                            #Path Traversal Detected
                            result.append(genFindingsDict(STATUS["INSECURE"]+" Path Traversal Vulnerability found on Request URI", url, "Check the Response Below", pt_res))

            #Scan in Request Body
            if request["body"]:
                scan_val = []
                request_bd = request
                body = request["body"]
                if re.findall("[\w\W]+\=[\w\W]+[&]*",body):
                    #possible key=value&key1=foo
                    try:
                        dict_qs = parse_qs(body)
                        #{key1: [val1], key2:[val1,val2]}
                        good = True
                    except:
                        good = False
                    if good:
                        for key in dict_qs:
                            for val in dict_qs[key]:
                                if (is_number(val) == False) and ("/" in val):
                                    scan_val.append(val)
                                if (is_number(val) == False) and (re.findall("^[\w]+[\W]*[\w]*[.][\w]{1,4}$",val)):
                                    #not a number and matches a filename with extension
                                    if re.findall("%40|@",val):
                                        #we don't want to test email fields
                                        pass
                                    else:
                                        scan_val.append(val)
                        for val in scan_val:
                            for payload in path_traversal_payloads(SCAN_MODE):
                                payload = payload.replace("{FILE}",settings.CHECK_FILE)
                                request_bd["body"] = body.replace(val,payload)
                                print "BODY", request_bd
                                bdpt_res = HTTP_Request(request_bd)
                                if bdpt_res:
                                    if (re.findall(settings.RESPONSE_REGEX,bdpt_res.body)):
                                        #Path Traversal Detected
                                        result.append(genFindingsDict(STATUS["INSECURE"]+" Path Traversal Vulnerability found on Request Body", url, "Check the Response Below", bdpt_res))

    except:
        PrintException("[ERROR] Path Traversal Tester")
    return result

#API Rate Limiting

def api_check_ratelimit(SCAN_REQUESTS,URLS_CONF):
    '''
    Detection Based on Response Code and Response Body Length
    '''
    global STATUS
    print "\n[INFO] Performing API Rate Limit Check"
    result = []
    try:
        LOGIN_API =[]
        PIN_API = []
        REGISTER_API = []
        for key,val in URLS_CONF.items():
            if val["login"]!="none":
                LOGIN_API.append(val["login"])
            if val["pin"]!="none":
                PIN_API.append(val["pin"])
            if val["register"]!="none":
                REGISTER_API.append(val["register"])

        LOGIN_API = list(set(LOGIN_API))
        PIN_API = list(set(PIN_API))
        REGISTER_API = list(set(REGISTER_API))

        for request in SCAN_REQUESTS:
            if request["url"] in REGISTER_API:
                
                #Register API Call Rate Limit Check
                '''
                We try to create random users to see if rate is limited.
                '''
                #URI 
                url = request["url"]
                qs = urlparse(url).query
                prev_url = url.replace(qs,"")
                dict_qs = parse_qs(qs)
                #BODY
                body_type=findBodyType(request)
                # We mutate body first and then URI, and not together.
                if body_type!="none":
                    print "\n[INFO] Register API Rate Limit Check - Checking in HTTP Request Body"
                    #Register Params in Body
                    stat, res = APIRateLimitCheck(request, body_type, "register", settings.RATE_REGISTER, False)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Register API is not rate limited", url, "API Tester created "+ str(settings.RATE_REGISTER) + " users by mutating HTTP body.", res))

                if dict_qs:
                    print "\n[INFO] Register API Rate Limit Check - Checking in HTTP Request URI"
                    #Register Parms in QS
                    stat, res = APIRateLimitCheck(request, "form", "register", settings.RATE_REGISTER, True)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Register API is not rate limited", url, "API Tester created "+ str(settings.RATE_REGISTER) + " users by mutating HTTP Query String.", res))
            
            elif request["url"] in LOGIN_API:
                
                #Login BruteForce
                '''
                We try to BruteForce with a wrong password to see if rate is limited
                '''
                #URI 
                url = request["url"]
                qs = urlparse(url).query
                prev_url = url.replace(qs,"")
                dict_qs = parse_qs(qs)
                #BODY
                body_type=findBodyType(request)
                # We mutate body first and then URI, and not together.
                if body_type!="none":
                    print "\n[INFO] Login API Rate Limit Check - Checking in HTTP Request Body"
                    #Login Params in Body
                    stat, res = APIRateLimitCheck(request, body_type, "login", settings.RATE_LOGIN, False)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Login API is not protected from bruteforce.", url, "API Tester bruteforced Login API "+ str(settings.RATE_LOGIN) + " times by modifying HTTP body without getting blocked.", res))
                if dict_qs:
                    print "\n[INFO] Login API Rate Limit Check - Checking in HTTP Request URI"
                    #Login Parms in QS
                    stat, res = APIRateLimitCheck(request, "form","login", settings.RATE_LOGIN, True)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Login API is not protected from bruteforce", url, "API Tester bruteforced Login API "+ str(settings.RATE_LOGIN) + " times by modifying HTTP Query String without getting blocked.", res))
            
            elif request["url"] in PIN_API:
                
                #Login by PIN BruteForce
                '''
                We try to BruteForce with a wrong pin to see if rate is limited
                '''
                #URI 
                url = request["url"]
                qs = urlparse(url).query
                prev_url = url.replace(qs,"")
                dict_qs = parse_qs(qs)
                #BODY
                body_type=findBodyType(request)
                # We mutate body first and then URI, and not together.
                if body_type!="none":
                    print "\n[INFO] Pin API Rate Limit Check - Checking in HTTP Request Body"
                    #Pin Param in Body
                    stat, res = APIRateLimitCheck(request, body_type, "pin", settings.RATE_LOGIN, False)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Pin API is not protected from bruteforce.", url, "API Tester bruteforced Pin API "+ str(settings.RATE_LOGIN) + " times by modifying HTTP body without getting blocked.", res))
                if dict_qs:
                    print "\n[INFO] Pin API Rate Limit Check - Checking in HTTP Request URI"
                    #Pin Parm in QS
                    stat, res = APIRateLimitCheck(request, "form", "pin", settings.RATE_LOGIN, True)
                    if stat == False:
                        result.append(genFindingsDict(STATUS["INSECURE"]+" Pin API is not protected from bruteforce", url, "API Tester bruteforced Pin API "+ str(settings.RATE_LOGIN) + " times by modifying HTTP Query String without getting blocked.", res))
    except:
        PrintException("[ERROR] API Rate Limit Tester")
    return result


# Helper Function
def HTTP_Request(req):
    print "\n[INFO] Making HTTP Requst to: " +  req["url"]
    response = None
    http_client = tornado.httpclient.HTTPClient()
    try:
        req = tornado.httpclient.HTTPRequest(**req)
        response = http_client.fetch(req)
    except tornado.httpclient.HTTPError as e:
        PrintException("[ERROR] HTTP Connection Error",True)
    except Exception as e:
        PrintException("[ERROR] HTTP GET Request Error")
    http_client.close()
    return response

def HTTP_GET_Request(url):
    response = None
    http_client = tornado.httpclient.HTTPClient()
    try:
        response = http_client.fetch(url)
    except tornado.httpclient.HTTPError as e:
        PrintException("[ERROR] HTTP Connection Error",True)
    except Exception as e:
        PrintException("[ERROR] HTTP GET Request Error")
    http_client.close()
    return response

def getListOfURLS(MD5,ALL):
    try:
        URLS = []
        APP_DIR=os.path.join(settings.UPLD_DIR,MD5+'/')
        with open(os.path.join(APP_DIR,"urls"),"r") as f:
            dat=f.read()
        dat = dat.split('\n')
        if ALL:
            return dat
        else:
            for x in dat:
                URLS.append(getProtocolDomain(x))
            URLS=list(set(URLS))
            return URLS
    except:
        PrintException("[ERROR] Getting List of URLS")

def getLogoutAPI(URLS_CONF):
    LOGOUT_API = []
    try:
        for key,val in URLS_CONF.items():
            LOGOUT_API.append(val["logout"])
        LOGOUT_API = list(set(LOGOUT_API))
    except:
        PrintException("[ERROR] Getting List of Logout APIs")
    return LOGOUT_API

def getScanRequests(MD5,SCOPE_URLS,URLS_CONF):
    try:
        print "\n[INFO] Getting Scan Request Objects"
        SCAN_REQUESTS=[]
        LOGOUT_REQUESTS=[]
        data = []
        LOGOUT_API = getLogoutAPI(URLS_CONF)
        APKDIR=os.path.join(settings.UPLD_DIR, MD5+'/')
        with io.open(os.path.join(APKDIR,"requestdb"), mode='r',encoding="utf8",errors="ignore") as fp:
            data = json.load(fp) #List of Request Dict
        for request in data:
            if getProtocolDomain(request["url"]) in SCOPE_URLS:
                if request["url"] in LOGOUT_API:
                    if request not in LOGOUT_REQUESTS:
                        LOGOUT_REQUESTS.append(request)
                else:
                    if request not in SCAN_REQUESTS:
                        SCAN_REQUESTS.append(request)
        return SCAN_REQUESTS, LOGOUT_REQUESTS
    except:
        PrintException("[ERROR] Getting Scan Request Objects")

def getRawRequestResponse(response,resbody):
    REQUEST = []
    RESPONSE = []
    req_object = {}
    try:
        REQUEST.append((response.request.method)+ " " + (response.request.url))
        for header, value in list(response.request.headers.items()):
            REQUEST.append(header + ": " + value)
        body = response.request.body if response.request.body else '' 
        body = "\n" + (body)
        REQUEST.append(body)

        RESPONSE.append(str(response.code) + " " + (response.reason))
        for header, value in list(response.headers.items()):
            RESPONSE.append(header + ": " + value)
        rbody = response.body if response.body else '' 
        rbody = "\n" + (rbody)
        if resbody:
            RESPONSE.append(rbody)

        REQUEST='\n'.join(REQUEST)
        RESPONSE='\n'.join(RESPONSE)
        req_object["req"]=REQUEST
        req_object["res"]=RESPONSE
    except:
        PrintException("[ERROR] Getting RAW Request/Response Pair")
    return req_object

def genFindingsDict(desc, url, proof, response, resp_body = False):
    findings = {}
    try:
        findings["techinfo"] = desc
        findings["url"] = url
        findings["proof"] = proof
        r = getRawRequestResponse(response,resp_body)
        findings["request"] = r["req"]
        findings["response"] = r["res"]
    except:
        PrintException("[ERROR] Constructing Findings")
    return findings

def extractURLS(string):
    urllist=[]
    ipport = []
    final = []
    try:

        p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE) 
        urllist = re.findall(p, string.lower())
        p = re.compile(ur'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\:[0-9]{1,5}', re.UNICODE) 
        ipport = re.findall(p, string.lower())

        final = list(set(ipport + urllist))

    except:
        PrintException("[ERROR] Extracting URLs and IP:PORT")
    return final

def getProtocolDomain(url):
    try:
        parsed_uri = urlparse(url)
        return '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    except:
        PrintException("[ERROR] Parsing Protocol and Domain")

def getIPList(url):
    #url = http://fooo.com:899/
    ips=[]
    HOSTNAME =''
    PORT ='80'
    try:
        o = urlparse(url)
        HOSTNAME = o.hostname
        if o.port:
            PORT = o.port
        else:
            if o.scheme == "http":
                PORT = 80
            elif o.scheme == "https":
                PORT = 443
        result = socket.getaddrinfo(HOSTNAME, PORT, 0, socket.SOCK_STREAM)
        for item in result:
            ips.append(item[4][0])
        ips = list(set(ips))
    except:
        PrintException("[ERROR] Getting IP(s) from URL")
    return ips

def findBetween(s, first, last):
    try :
        start = s.index(first) + len(first)
        end = s.index(last,start)
        return s[start:end]
    except ValueError:
        return ""

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

def getMD5(data):
    return hashlib.md5(data).hexdigest()

#SSRF and XXE
 
def deleteByIP(ip):
    try:
        res = HTTP_GET_Request(settings.CLOUD_SERVER +"/delete/"+ ip)
    except:
        PrintException("[ERROR] Deleting entries by IP from MobSF Cloud Server")

def getStatusByHash(md5):
    try:
        res = HTTP_GET_Request(settings.CLOUD_SERVER +"/md5/"+ md5)
        r = json.loads(res.body)
        if r["status"] == "yes":
            return "yes"
        else:
            return "no"
    except:
        PrintException("[ERROR] Checking Hash status from MobSF Cloud Server")
    return "no"

def getStatusByIP(url):
    try:
        for ip in getIPList(url):
            res = HTTP_GET_Request(settings.CLOUD_SERVER +"/ip/"+ ip)
            r = json.loads(res.body)
            if r["count"] != 0:
                #Clean IP state in MobSF Cloud Server
                deleteByIP(ip)
                return "yes"
        return "no"
    except:
        PrintException("[ERROR] Checking IP status from MobSF Cloud Server")
    return "no"

def getStatusByCount(count):
    try:
        res = HTTP_GET_Request(settings.CLOUD_SERVER +"/ip/ts")
        r = json.loads(res.body)
        if r["count"] >= count:
            return "yes"
        else:
            return "no"
    except:
        PrintException("[ERROR] Checking Status by Request Count from MobSF Cloud Server")
    return "no"

def xxe_paylods():
    XXE = []
    try:
        dat = ''
        PAYLOADS_DIR=os.path.join(settings.BASE_DIR, 'APITester/payloads/')
        with open(os.path.join(PAYLOADS_DIR,"xxe.txt"),"r") as f:
            dat=f.read()
        XXE = list(set(dat.split("\n")))
    except:
        PrintException("[ERROR] Reading XXE Payloads")
    return XXE

# Path Traversal

def path_traversal_payloads(SCAN_MODE):
    PT =[]
    N=15 #First 15 payloads
    try:
        dat = None
        PAYLOADS_DIR=os.path.join(settings.BASE_DIR, 'APITester/payloads/')
        with open(os.path.join(PAYLOADS_DIR,"path_traversal.txt"),"r") as f:
            if SCAN_MODE == "basic":
                dat= [next(f).replace("\n","") for x in xrange(N)]
                PT = list(set(dat))
            else:
                dat=f.read()
                PT = list(set(dat.split("\n")))
    except:
        PrintException("[ERROR] Reading Path Traversal Payloads")
    return PT

# Rate Limit

def findBodyType(request):
    bd_typ ="none"
    try:
        if request["body"]:
            try:
                json.loads(request["body"])
                bd_typ ="json"
            except:
                pass
            try:
                config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
                #Prevent Entity Expansion Attacks against the Framework
                etree.fromstring(request["body"],config)
                bd_typ ="xml"
            except:
                pass
            qs=parse_qs(request["body"])
            if qs:
                bd_typ="form"
        return bd_typ
    except:
        PrintException("[ERROR] Finding Request Body type")

def QSMutate(qs,typ):
    try:
        m_qs = qs
        if typ == "register":
            dict_qs = parse_qs(qs)
            for key in dict_qs:
                for val in dict_qs[key]:
                    if re.findall("%40|@",val):
                        #Do careful mutation for emails
                        m_email = choice(string.ascii_letters) + choice(string.ascii_letters) + choice(string.ascii_letters) + val[1:]
                        m_qs = m_qs.replace(val,m_email)
                    elif (len(val)> 1) and (val.lower()!= "true") and (val.lower()!="false"):
                        #Rest all thing like username, pin, password, mobile, just mutate characters
                        #String of length 1 is never mutated
                        listify = list (val)
                        shuffle(listify)
                        m_val = ''.join(listify)
                        m_qs = m_qs.replace(val,m_val)
        elif typ == "login":
            #Simple Logic - for timesake
            dict_qs = parse_qs(qs)
            for key in dict_qs:
                for val in dict_qs[key]:
                    if re.findall("pass|password|ps|userpass|pass-word",key,re.I):
                        listify = list (val)
                        shuffle(listify)
                        m_val = ''.join(listify)
                        m_qs = m_qs.replace(val,m_val)
        elif typ == "pin":
            #Simple Logic - for timesake
            dict_qs = parse_qs(qs)
            for key in dict_qs:
                for val in dict_qs[key]:
                    if re.findall("pin|passcode|cvv|code|passlock|lockcode",key,re.I):
                        listify = list (val)
                        shuffle(listify)
                        m_val = ''.join(listify)
                        m_qs = m_qs.replace(val,m_val)
        return m_qs
    except:
        PrintException("[ERROR] Mutating Query String")

def JSONMutate(json,typ):
    try:
        #Mutate only strings in 1st level, 2nd level and 3rd level nested dict 
        dic=json.loads(json)
        if typ == "register":
            for k in dic:
                if type(dic[k]) == str:
                    if re.findall("%40|@",dic[k]):
                        #Do careful mutation for emails
                        m_email = choice(string.ascii_letters) + choice(string.ascii_letters) + choice(string.ascii_letters) + dic[k][1:]
                        dic[k] = m_email
                    elif (len(dic[k])> 1) and (dic[k].lower()!= "true") and (dic[k].lower()!="false"):
                        listify = list (dic[k])
                        shuffle(listify)
                        dic[k] = ''.join(listify)
                elif type(dic[k]) == dict:
                    for kk in dic[k]:
                        if type(dic[k][kk]) == str:
                            if re.findall("%40|@",dic[k][kk]):
                                #Do careful mutation for emails
                                m_email = choice(string.ascii_letters) + choice(string.ascii_letters) + choice(string.ascii_letters) + dic[k][kk][1:]
                                dic[k][kk] = m_email
                            elif (len(dic[k][kk])> 1) and (dic[k][kk].lower()!= "true") and (dic[k][kk].lower()!="false"):
                                listify = list (dic[k][kk])
                                shuffle(listify)
                                dic[k][kk] = ''.join(listify)
                        elif type(dic[k][kk]) == dict:
                            for kkk in dic[k][kk]:
                                if type(dic[k][kk][kkk]) == str:
                                    if re.findall("%40|@",dic[k][kk][kkk]):
                                        #Do careful mutation for emails
                                        m_email = choice(string.ascii_letters) + choice(string.ascii_letters) + choice(string.ascii_letters) + dic[k][kk][kkk][1:]
                                        dic[k][kk][kkk] = m_email
                                    elif (len(dic[k][kk][kkk])> 1) and (dic[k][kk][kkk].lower()!= "true") and (dic[k][kk][kkk].lower()!="false"):
                                        listify = list (dic[k][kk][kkk])
                                        shuffle(listify)
                                        dic[k][kk][kkk] = ''.join(listify)
        elif typ == "login":
            #Simple Logic - for timesake
            #Only 1st Level is checked
            for k in dic:
                if type(k) == str:
                    if re.findall("pass|password|ps|userpass|pass-word",k,re.I):
                        if (type(dic[k]) == str):
                            listify = list (dic[k])
                            shuffle(listify)
                            dic[k] = ''.join(listify)
        elif typ == "pin":
            #Simple Logic - for timesake
            #Only 1st Level is checked
            for k in dic:
                if type(k) == str:
                    if re.findall("pin|passcode|cvv|code|passlock|lockcode",k,re.I):
                        if (type(dic[k]) == str):
                            listify = list (dic[k])
                            shuffle(listify)
                            dic[k] = ''.join(listify)
        return json.dumps(dic)
    except:
        PrintException("[ERROR] Mutating JSON data")

def XMLMutate(xml, typ):
    try:
        #IMPORTANT!!! Not Implemented Completely - Hack for the timesake
        creds = []
        if typ == "register":
            creds.append(findBetween(xml,"<user>","</user>"))
            creds.append(findBetween(xml,"<us>","</us>"))
            creds.append(findBetween(xml,"<user-name>","</user-name>"))
            creds.append(findBetween(xml,"<id>","</id>"))
            creds.append(findBetween(xml,"<username>","</username>"))
            creds.append(findBetween(xml,"<password>","</password>"))
            creds.append(findBetween(xml,"<pass>","</pass>"))
            creds.append(findBetween(xml,"<pas>","</pas>"))
            creds.append(findBetween(xml,"<ps>","</ps>"))
            creds.append(findBetween(xml,"<pin>","</pin>"))
            creds.append(findBetween(xml,"<passcode>","</passcode>"))
            creds.append(findBetween(xml,"<email>","</email>"))
            creds.append(findBetween(xml,"<e-mail>","</e-mail>"))
            creds.append(findBetween(xml,"<mobile>","</mobile>"))
            creds.append(findBetween(xml,"<mob>","</mob>"))
            creds.append(findBetween(xml,"<userid>","</userid>"))
            creds = list(set(creds))
            for x in creds:
                if re.findall("%40|@",x):
                    #Do careful mutation for emails
                    m_email = choice(string.ascii_letters) + choice(string.ascii_letters) + choice(string.ascii_letters) + x[1:]
                    xml = xml.replace(x,m_email)
                elif (len(x) > 1) and (x.lower()!="true") and (x.lower()!="false"):
                    listify = list (x)
                    shuffle(listify)
                    m_val = ''.join(listify)
                    xml = xml.replace(x,m_val)
        elif typ == "login":
            creds.append(findBetween(xml,"<password>","</password>"))
            creds.append(findBetween(xml,"<pass>","</pass>"))
            creds.append(findBetween(xml,"<pas>","</pas>"))
            creds.append(findBetween(xml,"<ps>","</ps>"))
            creds.append(findBetween(xml,"<PASSWORD>","</PASSWORD>"))
            creds.append(findBetween(xml,"<PASS>","</PASS>"))
            creds.append(findBetween(xml,"<PS>","</PS>"))

            creds = list(set(creds))
            for x in creds:
                if (len(x) > 1) and (x.lower()!="true") and (x.lower()!="false"):
                    listify = list (x)
                    shuffle(listify)
                    m_val = ''.join(listify)
                    xml = xml.replace(x,m_val)
        elif typ == "pin":
            creds.append(findBetween(xml,"<passcode>","</passcode>"))
            creds.append(findBetween(xml,"<pin>","</pin>"))
            creds.append(findBetween(xml,"<code>","</code>"))
            creds.append(findBetween(xml,"<passlock>","</passlock>"))
            creds.append(findBetween(xml,"<lockcode>","</lockcode>"))
            creds.append(findBetween(xml,"<cvv>","</cvv>"))
            creds = list(set(creds))
            for x in creds:
                if (len(x) > 1) and (x.lower()!="true") and (x.lower()!="false"):
                    listify = list (x)
                    shuffle(listify)
                    m_val = ''.join(listify)
                    xml = xml.replace(x,m_val)
        return xml
    except:
        PrintException("[ERROR] Mutating JSON data")

def APIRateLimitCheck(request, body_type, action, limit, isQS = False):
    print "\n[INFO] Checking "+action+" API Rate Limiting"
    res = {}
    try:
        if body_type == "form":
            frm_request = request
            dict_qs = {}
            if isQS:
                #HTTP Request URI
                url = request["url"]
                qs = urlparse(url).query
                prev_url = url.replace(qs,"")
                frm_request["url"] = prev_url + QSMutate(qs,action)
                #Make first mutated request and collect response code and body
                res=HTTP_Request(frm_request)
                if res:
                    if res.code:
                        res_code = str(res.code)
                        if (res_code[0] == "4") or (res_code[0] == "5"):
                            # If response code is 4XX or 5XX
                            return True, res
                else:
                    return True, res
                if res.error:
                    #If Initial Request is failing, no point of checking again
                    print "URI - Response Error"
                    return True, res
                else:
                    initial_res = res
                    for x in range(limit):
                        frm_request["url"] = prev_url + QSMutate(qs,action)
                        res = HTTP_Request(frm_request)
                    if res.error:
                        print "URI - Response Error"
                        return True, res
                    else:
                        if res.code == initial_res.code:
                            bd = False
                            if res.body and initial_res.body:
                                bd = True
                            if bd:
                                if len(res.body) == len(initial_res.body):
                                    return False, res #W00t no Rate Limit Check/Captcha in place
                                else:
                                    return True, res
                            else:
                                return False, res  #W00t no Rate Limit Check/Captcha in place
                        else:
                            return True, res
                return True,res
            else:
                #HTTP Request Body
                
                frm_request["body"] = QSMutate(request["body"],action)
                #Make first mutated request and collect response code and body

                res=HTTP_Request(frm_request)
                if res:
                    if res.code:
                        res_code = str(res.code)
                        if (res_code[0] == "4") or (res_code[0] == "5"):
                            # If response code is 4XX,5XX
                            return True, res
                else:
                    return True, res
                if res.error:
                    #If Initial Request is failing, no point of checking again
                    print "Form Body - Response Error"
                    return True, res
                else:
                    initial_res = res
                    for x in range(limit):
                        frm_request["body"] = QSMutate(request["body"],action)
                        res = HTTP_Request(frm_request)
                    if res.error:
                        print "Form Body - Response Error"
                        return True, res
                    else:
                        if res.code == initial_res.code:
                            bd = False
                            if res.body and initial_res.body:
                                bd = True
                            if bd:
                                if len(res.body) == len(initial_res.body):
                                    return False, res #W00t no Rate Limit Check/Captcha in place
                                else:
                                    return True, res
                            else:
                                return False, res  #W00t no Rate Limit Check/Captcha in place
                        else:
                            return True, res
            return True, res
        elif body_type == "json":
            json_request = request
            json_request["body"] = JSONMutate(request["body"],action)
            res = HTTP_Request(json_request)
            if res:
                if res.code:
                    res_code = str(res.code)
                    if (res_code[0] == "4") or (res_code[0] == "5"):
                        # If response code is 4XX, 5XX
                        return True, res
            else:
                return True, res
            if res.error:
                #If Initial Request is failing, no point of checking again
                print "JSON Body - Response Error"
                return True, res
            else:
                initial_res = res
                for x in range(limit):
                    json_request["body"] = JSONMutate(request["body"],action)
                    res = HTTP_Request(json_request)
                if res.error:
                    print "JSON Body - Response Error"
                    return True, res
                else:
                    if res.code == initial_res.code:
                        bd = False
                        if res.body and initial_res.body:
                            bd = True
                        if bd:
                            if len(res.body) == len(initial_res.body):
                                return False, res #W00t no Rate Limit Check/Captcha in place
                            else:
                                return True, res
                        else:
                            return False, res  #W00t no Rate Limit Check/Captcha in place
                    else:
                        return True, res
        elif body_type == "xml":
            xml_request = request
            xml_request["body"] = XMLMutate(request["body"],action)
            res = HTTP_Request(xml_request)
            if res:
                if res.code:
                    res_code = str(res.code)
                    if (res_code[0] == "4") or (res_code[0] == "5"):
                        # If response code is 4XX, 5XX
                        return True, res
            else:
                return True, res
            if res.error:
                #If Initial Request is failing, no point of checking again
                print "XML Body - Response Error"
                return True, res
            else:
                initial_res = res
                for x in range(limit):
                    xml_request["body"] = XMLMutate(request["body"],action)
                    res = HTTP_Request(xml_request)
                if res.error:
                    print "XML Body - Response Error"
                    return True, res
                else:
                    if res.code == initial_res.code:
                        bd = False
                        if res.body and initial_res.body:
                            bd = True
                        if bd:
                            if len(res.body) == len(initial_res.body):
                                return False, res #W00t no Rate Limit Check/Captcha in place
                            else:
                                return True, res
                        else:
                            return False, res  #W00t no Rate Limit Check/Captcha in place
                    else:
                        return True, res
        return True, res # Means RateLimitCheck exists or We just failed.
    except:
        PrintException("[ERROR] Checking "+action+" API Rate Limiting")

