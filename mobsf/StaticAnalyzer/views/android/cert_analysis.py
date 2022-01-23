# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import binascii
import hashlib
import logging
import os
import re

from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string

from asn1crypto import x509

from oscrypto import asymmetric

from django.utils.html import escape

logger = logging.getLogger(__name__)
logging.getLogger('androguard').setLevel(logging.ERROR)


def get_hardcoded_cert_keystore(files):
    """Returns the hardcoded certificate keystore."""
    try:
        logger.info('Getting Hardcoded Certificates/Keystores')
        findings = []
        certz = []
        key_store = []
        for file_name in files:
            if '.' not in file_name:
                continue
            ext = file_name.split('.')[-1]
            if re.search('cer|pem|cert|crt|pub|key|pfx|p12|der', ext):
                certz.append(escape(file_name))
            if re.search('jks|bks', ext):
                key_store.append(escape(file_name))
        if certz:
            desc = 'Certificate/Key files hardcoded inside the app.'
            findings.append({'finding': desc, 'files': certz})
        if key_store:
            desc = 'Hardcoded Keystore found.'
            findings.append({'finding': desc, 'files': key_store})
        return findings
    except Exception:
        logger.exception('Getting Hardcoded Certificates/Keystores')


def cert_info(app_dir, app_file):
    """Return certificate information."""
    try:
        logger.info('Reading Code Signing Certificate')
        manifestfile = None
        manidat = ''
        cert_info = ''
        certlist = []
        cert_path = os.path.join(app_dir, 'META-INF/')

        apk_file = os.path.join(app_dir, app_file)
        hashfunctions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }
        files = [f for f in os.listdir(
            cert_path) if os.path.isfile(os.path.join(cert_path, f))]
        a = APK(apk_file)
        if a.is_signed():
            certlist.append('APK is signed')
        else:
            certlist.append('Missing certificate')
        certlist.append('v1 signature: {}'.format(a.is_signed_v1()))
        certlist.append('v2 signature: {}'.format(a.is_signed_v2()))
        certlist.append('v3 signature: {}'.format(a.is_signed_v3()))

        certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2()
                    + [a.get_certificate_der(x)
                       for x in a.get_signature_names()])
        pkeys = set(a.get_public_keys_der_v3() + a.get_public_keys_der_v2())

        if len(certs) > 0:
            certlist.append('Found {} unique certificates'.format(len(certs)))

        for cert in certs:
            x509_cert = x509.Certificate.load(cert)
            certlist.append('Subject: {}'.format(
                get_certificate_name_string(x509_cert.subject, short=True)))
            certlist.append('Signature Algorithm: {}'.format(
                x509_cert.signature_algo))
            certlist.append('Valid From: {}'.format(
                x509_cert['tbs_certificate']['validity']['not_before'].native))
            certlist.append('Valid To: {}'.format(
                x509_cert['tbs_certificate']['validity']['not_after'].native))
            certlist.append('Issuer: {}'.format(
                get_certificate_name_string(x509_cert.issuer, short=True)))
            certlist.append('Serial Number: {}'.format(
                hex(x509_cert.serial_number)))
            certlist.append('Hash Algorithm: {}'.format(x509_cert.hash_algo))
            for k, v in hashfunctions.items():
                certlist.append('{}: {}'.format(k, v(cert).hexdigest()))

        for public_key in pkeys:
            x509_public_key = asymmetric.load_public_key(public_key)
            certlist.append('PublicKey Algorithm: {}'.format(
                x509_public_key.algorithm))
            certlist.append('Bit Size: {}'.format(x509_public_key.bit_size))
            certlist.append('Fingerprint: {}'.format(
                binascii.hexlify(x509_public_key.fingerprint).decode('utf-8')))
        cert_info = '\n'.join(certlist)
        if 'MANIFEST.MF' in files:
            manifestfile = os.path.join(cert_path, 'MANIFEST.MF')
        if manifestfile:
            with open(manifestfile, 'r', encoding='utf-8') as manifile:
                manidat = manifile.read()
        sha256_digest = bool(re.findall(r'SHA-256-Digest', manidat))
        findings = []
        if a.is_signed():
            findings.append((
                'info',
                'Application is signed with a code '
                'signing certificate',
                'Signed Application'))
        else:
            findings.append((
                'high',
                'Code signing certificate not found',
                'Missing Code Signing certificate'))
        if a.is_signed_v1():
            status = 'high'
            if a.is_signed_v2() or a.is_signed_v3():
                status = 'warning'
            findings.append((
                status,
                'Application is signed with v1 signature scheme, '
                'making it vulnerable to Janus vulnerability on '
                'Android 5.0-8.0, if signed only with v1 signature'
                ' scheme. Applications running on Android 5.0-7.0'
                ' signed with v1, and v2/v3 '
                'scheme is also vulnerable.',
                'Application vulnerable to Janus Vulnerability'))
        if re.findall(r'CN=Android Debug', cert_info):
            findings.append((
                'high',
                'Application signed with a debug certificate. '
                'Production application must not be shipped '
                'with a debug certificate.',
                'Application signed with debug certificate'))
        if re.findall(r'Hash Algorithm: sha1', cert_info):
            status = 'high'
            desc = (
                'Application is signed with SHA1withRSA. '
                'SHA1 hash algorithm is known to have '
                'collision issues.')
            title = 'Certificate algorithm vulnerable to hash collision'
            if sha256_digest:
                status = 'warning'
                desc += (
                    ' The manifest file indicates SHA256withRSA'
                    ' is in use.')
            title = ('Certificate algorithm might be '
                     'vulnerable to hash collision')
            findings.append((status, desc, title))
        cert_dic = {
            'certificate_info': cert_info,
            'certificate_findings': findings,
        }
        return cert_dic
    except Exception:
        logger.exception('Reading Code Signing Certificate')
        return {}
