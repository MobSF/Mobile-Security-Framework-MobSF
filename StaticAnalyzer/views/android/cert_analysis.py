# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import subprocess
import re
import os

from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)

import logging
logger = logging.getLogger(__name__)


def get_hardcoded_cert_keystore(files):
    """Returns the hardcoded certificate keystore."""
    try:
        logger.info("Getting Hardcoded Certificates/Keystores")
        dat = ''
        certz = ''
        key_store = ''
        for file_name in files:
            ext = file_name.split('.')[-1]
            if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                certz += escape(file_name) + "</br>"
            if re.search("jks|bks", ext):
                key_store += escape(file_name) + "</br>"
        if len(certz) > 1:
            dat += (
                "<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>" +
                certz +
                "</td><tr>"
            )
        if len(key_store) > 1:
            dat += "<tr><td>Hardcoded Keystore Found.</td><td>" + key_store + "</td><tr>"
        return dat
    except:
        PrintException("Getting Hardcoded Certificates/Keystores")


def cert_info(app_dir, tools_dir):
    """Return certificate information."""
    try:
        logger.info("Reading Code Signing Certificate")
        cert = os.path.join(app_dir, 'META-INF/')
        cp_path = tools_dir + 'CertPrint.jar'
        files = [f for f in os.listdir(
            cert) if os.path.isfile(os.path.join(cert, f))]
        certfile = None
        dat = ''
        manidat = ''
        manifestfile = None
        if "CERT.RSA" in files:
            certfile = os.path.join(cert, "CERT.RSA")
        else:
            for file_name in files:
                if file_name.lower().endswith(".rsa"):
                    certfile = os.path.join(cert, file_name)
                elif file_name.lower().endswith(".dsa"):
                    certfile = os.path.join(cert, file_name)
        if certfile:
            args = [settings.JAVA_PATH + 'java', '-jar', cp_path, certfile]
            issued = 'good'
            dat = subprocess.check_output(args)
            unicode_output = str(dat, encoding="utf-8", errors="replace")
            dat = escape(unicode_output).replace('\n', '</br>')
        else:
            dat = 'No Code Signing Certificate Found!'
            issued = 'missing'
        if re.findall(r"Issuer: CN=Android Debug|Subject: CN=Android Debug", dat):
            issued = 'bad'
        if re.findall(r"\[SHA1withRSA\]", dat):
            issued = 'bad hash'
        if "MANIFEST.MF" in files:
            manifestfile = os.path.join(cert, "MANIFEST.MF")
        if manifestfile:
            with open(manifestfile,'r', encoding='utf-8') as manifile:
                manidat = manifile.read()
        sha256Digest = bool(re.findall(r"SHA-256-Digest", manidat))
        cert_dic = {
            'cert_info': dat,
            'issued': issued,
            'sha256Digest': sha256Digest
        }
        return cert_dic
    except:
        PrintException("Reading Code Signing Certificate")
