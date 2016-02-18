# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
import tornado.httpclient
import os,re,json,io
from urlparse import urlparse
from MobSF.exception_printer import PrintException

URLS_DICT = {}
def APITester(request):
	global URLS_DICT
	print "\n[INFO] API Testing Started"
	try:
		URLS=[]
		TESTS={0:'Information Gathering',1:'Security Headers',2:'Insecure Direct Object Reference',3:'Session Handling',4:'SSRF',5:'XXE',6:'Directory Traversal' }
		if request.method == 'GET':
			MD5=request.GET['md5']
			m=re.match('[0-9a-f]{32}',MD5)
			if m:
				dat=''
				APP_DIR=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/')
				with open(os.path.join(APP_DIR,"urls"),"r") as f:
					dat=f.read()
				dat = dat.split('\n')
				for x in dat:
					URLS.append(getProtocolDomain(x))
				URLS=list(set(URLS))
				URLS_DICT=dict(enumerate(URLS))
				context = {'title' : 'API Tester',
					'md5' : MD5,
					'urls' : URLS_DICT,
					'tests': TESTS,}
				template="api_tester.html"
				return render(request,template,context)
			else:
				return HttpResponseRedirect('/error/')
		elif request.method =="POST":
			MD5=request.POST['md5']
			m=re.match('[0-9a-f]{32}',MD5)
			if m:
				RESULT={}
				SCOPE_URLS =[]
				SCOPE=request.POST.getlist('scope')
				SELECTED_TESTS=request.POST.getlist('tests')
				for s in SCOPE:
					SCOPE_URLS.append(URLS_DICT.values()[int(s)])
				#
				print SCOPE_URLS
				for t in SELECTED_TESTS:
					print TESTS.values()[int(t)]
				#
				SCAN_REQUESTS = getScanRequests(MD5,SCOPE_URLS) #List of Request Dict that we need to scan
				if '0' in SELECTED_TESTS:
					RESULT['info_gathering'] = info_gathering(SCAN_REQUESTS,SCOPE_URLS)
					print RESULT['info_gathering']
				context = {'title' : 'API Tester',
					'md5' : MD5,
					'urls' : URLS_DICT,
					'tests': TESTS,}
				template="api_tester.html"
				return render(request,template,context)
			else:
				return HttpResponseRedirect('/error/')
		else:
			return HttpResponseRedirect('/error/')
	except:
		PrintException("[ERROR] APITester")
		return HttpResponseRedirect('/error/')

def info_gathering(SCAN_REQUESTS,SCOPE_URLS):
	print "\n[INFO] Performing Information Gathering"
	result = []
	try:
		#Initally Do on Scope URLs
		for url in SCOPE_URLS:
			response = HTTP_GET_Request(url)
			if not response == None:
				for header, value in list(response.headers.items()):
					if header.lower() == "server":
						findings = {}
						findings["serverinfo"] = "Server Information Disclosure"
						findings["url"] = url
						findings["header"] = header + ": " +value
						findings["request_response"] = getRawRequestResponse(response) #List of two string.
						result.append(findings)
					elif header.lower() == "x-powered-by":
						findings = {}
						findings["techinfo"] = "Technology Information Disclosure"
						findings["url"] = url
						findings["header"] = header + ": " +value
						findings["request_response"] = getRawRequestResponse(response) #List of two string.
						result.append(findings)
					elif header.lower() == "x-aspnetmvc-version":
						findings = {}
						findings["techinfo"] = "ASP.NET MVC Version Disclosure"
						findings["url"] = url
						findings["header"] = header + ": " +value
						findings["request_response"] = getRawRequestResponse(response) #List of two string.
						result.append(findings)
					elif header.lower() == "x-aspnet-version":
						findings = {}
						findings["techinfo"] = "ASP.NET Version Disclosure"
						findings["url"] = url
						findings["header"] = header + ": " +value
						findings["request_response"] = getRawRequestResponse(response) #List of two string.
						result.append(findings)




		'''
		for req in SCAN_REQUESTS:
			response=HTTP_Request(req)
		'''
	except:
		PrintException("[ERROR] Information Gathering Module")
	return result

# Helper Function

def HTTP_Request(req):
	response = None
	http_client = tornado.httpclient.HTTPClient()
	try:
		req = tornado.httpclient.HTTPRequest(**req)
		response = http_client.fetch(req)
	except tornado.httpclient.HTTPError as e:
		PrintException("[ERROR] HTTP Connection Error")
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
		PrintException("[ERROR] HTTP Connection Error")
	except Exception as e:
		PrintException("[ERROR] HTTP GET Request Error")
	http_client.close()
	return response

def getProtocolDomain(url):
	parsed_uri = urlparse(url)
	return '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

def getScanRequests(MD5,SCOPE_URLS):
	SCAN_REQUESTS=[]
	data = []
	APKDIR=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/')
	with io.open(os.path.join(APKDIR,"requestdb"), mode='r',encoding="utf8",errors="ignore") as fp:
		data = json.load(fp) #List of Request Dict
	for request in data:
		if getProtocolDomain(request["url"]) in SCOPE_URLS:
			SCAN_REQUESTS.append(request)
	return SCAN_REQUESTS

def getRawRequestResponse(response):
	REQUEST = []
	RESPONSE = []
	req_object = []
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
		RESPONSE.append(rbody)

		REQUEST='\n'.join(REQUEST)
		RESPONSE='\n'.join(RESPONSE)
		req_object.append(REQUEST)
		req_object.append(RESPONSE)

	except:
		PrintException("[ERROR] Getting RAW Request/Response Pair")
	return req_object