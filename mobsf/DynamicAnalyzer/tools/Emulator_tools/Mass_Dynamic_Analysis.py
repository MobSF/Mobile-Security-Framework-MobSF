#!/usr/bin/env python
# Mass Dynamic Analysis
import argparse
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import requests
serverpath = 'http://localhost:8002/'
#Please change this to your individual Rest API Key found in Mob_SF Rest API Docs
api_key = "Authorization:9adb741acc70d0f088bd47a41ca867c9437c88bf5486051eb35de71922da90b3"
hash = '056d831fb3f4423ea395c02d68841887'
venv_base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
output_folder = os.path.join(venv_base_directory, "Emulator_tools/MobSF_Reports/{}")
output_folder = os.path.expanduser(output_folder)
script_path = os.path.join(venv_base_directory, "frida_scripts/others")
script_path = os.path.expanduser(script_path)


def is_server_up(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.URLError:
        pass
    return False


def start_scan(directory, server_url, apikey, rescan='0'):
    print('\nLooking for Android/iOS/Windows binaries or source code in: ' + directory)
    logging.info('Uploading to MobSF Server')
    uploaded = []
    mimes = {
        '.apk': 'application/octet-stream',
        '.ipa': 'application/octet-stream',
        '.appx': 'application/octet-stream',
        '.zip': 'application/zip',
    }
    for filename in os.listdir(directory):
        fpath = os.path.join(directory, filename)
        _, ext = os.path.splitext(fpath)
        if ext in mimes:
            if ext in mimes:
                with open(fpath, 'rb') as f:
                    files = {'file': (filename, f, mimes[ext], {'Expires': '0'})}
                    response = requests.post(server_url + '/api/v1/upload', files=files, headers={'AUTHORIZATION': apikey})

            if response.status_code == 200 and 'hash' in response.json():
                logging.info('[OK] Upload OK: %s', filename)
                uploaded.append(response.json())
            else:
                logging.error('Performing Upload: %s', filename)

    for upl in uploaded:
        analysis_functions(upl['hash'])

def analysis_functions(hash):
    logging.info('Started Dynamic Analysis for: %s', hash)
    # Start analysis
    start_analysis(hash)
    time.sleep(10)
    #getting dependencies
    get_dependencies(hash)
    time.sleep(10)
    # Run Frida instrumentation
    frida_instrumentation(hash, "monitor_bytes.js")
    time.sleep(10)
    # Stop analysis
    stop_analysis(hash)
    time.sleep(10)
    # Generate report
    generate_report(hash)

def start_analysis(hash):
    api_path = serverpath + 'api/v1/dynamic/start_analysis'
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', api_key],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.flush()
    error = response.communicate()
    if response.returncode != 0:
        logging.info(f"Error starting dynamic analysis" + error.decode('utf-8'))
    else:
        logging.info("Dynamic analysis has successfully started")
            

def generate_report(hash):
    api_path = serverpath + 'api/v1/dynamic/report_json'
    logging.info('generating dynamic analysis report')
    output_full_path = output_folder.format(hash) + '/' + 'JSON REPORT-{}'.format(hash) + '.json'
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', api_key, '--output', output_full_path],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("JSON report generation is unsuccessful")
    else:
        logging.info("JSON report generation is successful")

def test_activities(hash):
    api_path = serverpath + 'api/v1/android/activity'
    exported_header = 'hash={}&test=exported'.format(hash)
    activity_header = 'hash={}&test=activity'.format(hash)
    exported = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', exported_header, '-H', api_key],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error_exported = exported.communicate()
    if exported.returncode != 0:
        logging.info("Error with testing exported activities" + error_exported.decode('utf-8'))
    else:
        logging.info("Successfully tested exported activties")
        activity = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', activity_header, '-H', api_key],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error_activity = activity.communicate()
        if activity.returncode != 0 :
            logging.info("Error in testing for activties" + error_activity.decode('utf-8'))
        else:
            logging.info("Successfully tested for activities")


    # If tls test is desired, append 'aysnc' to this function and uncomment the await line
def get_dependencies(hash):
    #await tls_ssl_test()
    api_path = serverpath + 'api/v1/frida/get_dependencies'
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', api_key],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("Getting dependencies unsuccessful" + error.decode('utf-8'))
    else:
        logging.info("Getting dependencies successful")

def frida_instrumentation(hash, script_name):
    api_path = serverpath + 'api/v1/frida/instrument'
    full_script_path = script_path + '/' + script_name
    file = open(full_script_path, "r")
    script_contents = file.read()
    file.close()
    parsed_script_contents = urllib.parse.quote_plus(script_contents)
    header = "hash={}&default_hooks=api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass&auxiliary_hooks=enum_class,string_catch,string_compare,enum_methods,search_class,trace_class&class_name=java.io.File&class_search=ssl&class_trace=javax.net.ssl.TrustManager&frida_code={}".format(hash,parsed_script_contents)
    response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', api_key],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("Frida script instrumentation unsuccessful.\nError: " + error.decode('utf-8'))
    else:
        logging.info("Frida script instrumentation successful")


def stop_analysis(hash):
    api_path = serverpath + 'api/v1/dynamic/stop_analysis'
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', api_key],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("Stopping of dynamic analysis is unsuccessful" + error.decode('utf-8'))
    else:
        logging.info("Stopping of dynamic analysis is successful")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help='Path to the directory that contains mobile app binary/zipped source code')
    parser.add_argument('-s', '--ipport', help='IP address and Port number of a running MobSF Server. (ex: 127.0.0.1:8000)')
    parser.add_argument('-k', '--apikey', help='MobSF REST API Key')
    parser.add_argument('-r', '--rescan', help='Run a fresh scan. Value can be 1 or 0 (Default: 0)')
    args = parser.parse_args()

    if args.directory and args.ipport and args.apikey:
        server = args.ipport
        directory = args.directory
        server_url = 'http://' + server
        apikey = args.apikey
        rescan = args.rescan
        if not is_server_up(server_url):
            print('MobSF REST API Server is not running at ' + server_url)
            print('Exiting!')
            exit(0)
        # MobSF is running, start scan
        start_scan(directory, server_url, apikey, rescan)
    else:
        parser.print_help()