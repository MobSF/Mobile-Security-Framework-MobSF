# -*- coding: utf_8 -*-
#Module for Malware Analysis
from urlparse import urlparse
import urllib2
import shutil
import io
import os
import re
import tempfile

from django.conf import settings

from MobSF.utils import (
    PrintException, isInternetAvailable, sha256
)

# PATH
MALWARE_DB_DIR = TOOLS_DIR = os.path.join(
    settings.BASE_DIR, 'MalwareAnalyzer/malwaredb/')


def apkid_analysis(app_dir):
    """APKiD Analysis of DEX file"""
    if settings.APKID_ENABLED:
        from StaticAnalyzer.tools.apkid import apkid
        apkid_dict = {}
        print "[INFO] APKiD Analysis on Dex file"
        dex_file = app_dir + 'classes.dex'
        result = apkid.scan(dex_file, 30, True)
        if "files" in result:
            apkid_dict["result"] = result["files"][0]["results"]
        if "apkid_version" in result:
            apkid_dict["apkid_version"] = result["apkid_version"]

        if "anti_vm" in apkid_dict["result"]:
            apkid_dict["anti_vm"] = apkid_dict["result"]["anti_vm"]
        else:
            apkid_dict["anti_vm"] = ""

        if "compiler" in apkid_dict["result"]:
            apkid_dict["compiler"] = apkid_dict["result"]["compiler"]
        else:
            apkid_dict["compiler"] = ""

        if "packer" in apkid_dict["result"]:
            apkid_dict["packer"] = apkid_dict["result"]["packer"]
        else:
            apkid_dict["packer"] = ""

        if "obfuscator" in apkid_dict["result"]:
            apkid_dict["obfuscator"] = apkid_dict["result"]["obfuscator"]
        else:
            apkid_dict["obfuscator"] = ""

        if "abnormal" in apkid_dict["result"]:
            apkid_dict["abnormal"] = apkid_dict["result"]["abnormal"]
        else:
            apkid_dict["abnormal"] = ""

        if "anti_disassembly" in apkid_dict["result"]:
            apkid_dict["anti_disassembly"] = apkid_dict[
                "result"]["anti_disassembly"]
        else:
            apkid_dict["anti_disassembly"] = ""

        if "dropper" in apkid_dict["result"]:
            apkid_dict["dropper"] = apkid_dict["result"]["dropper"]
        else:
            apkid_dict["dropper"] = ""

        if "manipulator" in apkid_dict["result"]:
            apkid_dict["manipulator"] = apkid_dict["result"]["manipulator"]
        else:
            apkid_dict["manipulator"] = ""

        apkid_dict["result"] = ""
        return apkid_dict
    return {}


def update_malware_db():
    """Check for update in malware DB"""
    try:
        url = "https://www.malwaredomainlist.com/mdlcsv.php"
        response = urllib2.urlopen(url)
        data = response.read()
        tmp_dwd = tempfile.NamedTemporaryFile()
        tmp_dwd.write(data)
        mal_db = os.path.join(MALWARE_DB_DIR, 'malwaredomainlist')
        # Check1: SHA256 Change
        if sha256(tmp_dwd.name) != sha256(mal_db):
            # DB needs update
            # Check2: DB Syntax Changed
            dptr = io.open(tmp_dwd.name, mode='r',
                           encoding="utf8", errors="ignore")
            line = dptr.readline()
            dptr.close()
            lst = line.split('",')
            if len(lst) == 10:
                # DB Format is not changed. Let's update DB
                print "\n[INFO] Updating Malware Database...."
                shutil.copyfile(tmp_dwd.name, mal_db)
            else:
                print "\n[WARNING] Malware Database format from malwaredomainlist.com changed. Database is not updated. Please report to: https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues"
        else:
            print "\n[INFO] Malware Database is up-to-date."
        tmp_dwd.close()
    except:
        PrintException("[ERROR] Malware DB Update")


def malware_check(urllist):
    result = {}
    domainlist = list()
    try:
        domainlist = get_domains(urllist)
        if domainlist:
            if isInternetAvailable():
                update_malware_db()
            else:
                print "\n[WARNING] No Internet Connection. Skipping Malware Database Update."
            mal_db = os.path.join(MALWARE_DB_DIR, 'malwaredomainlist')
            with io.open(mal_db, mode='r', encoding="utf8", errors="ignore") as flip:
                entry_list = flip.readlines()
            for entry in entry_list:
                enlist = entry.split('","')
                if len(enlist) > 5:
                    details_dict = dict()
                    details_dict["domain_or_url"] = enlist[1]
                    details_dict["ip"] = enlist[2]
                    details_dict["desc"] = enlist[4]
                    details_dict["bad"] = "yes"
                    for domain in domainlist:
                        if (details_dict["domain_or_url"].startswith(domain) or
                                details_dict["ip"].startswith(domain)):
                            result[domain] = details_dict
            # Good Domains
            for domain in domainlist:
                if domain not in result:
                    tmp_d = dict()
                    tmp_d["bad"] = "no"
                    result[domain] = tmp_d
    except:
        PrintException("[ERROR] Performing Malware Check")
    return result

# Helper Functions


def get_domains(urls):
    """Get Domains"""
    try:
        domains = list()
        for url in urls:
            parsed_uri = urlparse(url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            if ((domain not in domains) and
                    (len(domain) > 2) and
                    ("." in domain) and
                    (domain.endswith(".") is False and re.search('[a-zA-Z0-9]', domain))):
                domains.append(domain)
        return domains
    except:
        PrintException("[ERROR] Extracting Domain form URL")
        pass
