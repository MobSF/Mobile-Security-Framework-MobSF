import requests

from MobSF.utils import PrintException
from django.conf import settings
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'


def get_report(file_hash):
    global BASE_URL
    '''
    :param file_hash: md5/sha1/sha256
    :return: json response / None
    '''
    try:
        url = BASE_URL + 'report'
        params = {
            'apikey': settings.VT_API_KEY,
            'resource': file_hash
        }
        headers = {"Accept-Encoding": "gzip, deflate"}
        try:
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 403:
                print "[ERROR] VirusTotal Permission denied, wrong api key?"
                return None
        except:
            print "[ERROR] VirusTotal ConnectionError, check internet connectivity"
            return None

        json_response = response.json()
        return json_response

    except:
        PrintException("[ERROR] in VirusTotal get_report")
        return None


def upload_file(file_path):
    global VT_API_KEY, BASE_URL
    '''
    :param file_path: file path to upload
    :return: json response / None
    '''
    try:
        url = BASE_URL + "scan"
        files = {
            'file': open(file_path, 'rb')
        }
        headers = {
            "apikey": settings.VT_API_KEY
        }
        try:
            response = requests.post(url, files=files, data=headers)
            if response.status_code == 403:
                print "[ERROR] VirusTotal Permission denied, wrong api key?"
                return None
        except:
            print "[ERROR] VirusTotal ConnectionError, check internet connectivity"
            return None
        json_response = response.json()
        return json_response

    except:
        PrintException("[ERROR] in VirusTotal upload_file")
        return None


def get_result(file_path, file_hash):
    '''
    Uoloading a file and getting the approval msg from VT or fetching existing report
    :param file_path: file's path
    :param file_hash: file's hash - md5/sha1/sha256
    :return: VirusTotal result json / None upon error
    '''
    try:
        print "[INFO] VirusTotal: Check for existing report"
        report = get_report(file_hash)
        # Check for existing report
        if report:
            if report['response_code'] == 1:
                print "[INFO] VirusTotal: " + report['verbose_msg']
                return report
        print "[INFO] VirusTotal: " + report['verbose_msg']
        print "[INFO] VirusTotal: file upload"
        upload_response = upload_file(file_path)
        if upload_response:
            print "[INFO] VirusTotal: " + upload_response['verbose_msg']
        return None
    except:
        PrintException("[ERROR] in VirusTotal get_result")
