# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import binascii
import hashlib
import logging
import os
import re
import subprocess
from pathlib import Path

from androguard.util import get_certificate_name_string

from asn1crypto import x509

from oscrypto import asymmetric

from django.utils.html import escape

from mobsf.MobSF.utils import (
    find_java_binary,
)

logger = logging.getLogger(__name__)
ANDROID_8_1_LEVEL = 27
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
HASH_FUNCS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}


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


def get_cert_details(data):
    """Get certificate details."""
    certlist = []
    x509_cert = x509.Certificate.load(data)
    subject = get_certificate_name_string(x509_cert.subject, short=True)
    certlist.append(f'X.509 Subject: {subject}')
    certlist.append(f'Signature Algorithm: {x509_cert.signature_algo}')
    valid_from = x509_cert['tbs_certificate']['validity']['not_before'].native
    certlist.append(f'Valid From: {valid_from}')
    valid_to = x509_cert['tbs_certificate']['validity']['not_after'].native
    certlist.append(f'Valid To: {valid_to}')
    issuer = get_certificate_name_string(x509_cert.issuer, short=True)
    certlist.append(f'Issuer: {issuer}')
    certlist.append(f'Serial Number: {hex(x509_cert.serial_number)}')
    certlist.append(f'Hash Algorithm: {x509_cert.hash_algo}')
    for k, v in HASH_FUNCS.items():
        certlist.append(f'{k}: {v(data).hexdigest()}')
    return certlist


def get_pub_key_details(data):
    """Get public key details."""
    certlist = []
    x509_public_key = asymmetric.load_public_key(data)
    certlist.append(f'PublicKey Algorithm: {x509_public_key.algorithm}')
    certlist.append(f'Bit Size: {x509_public_key.bit_size}')
    fp = binascii.hexlify(x509_public_key.fingerprint).decode('utf-8')
    certlist.append(f'Fingerprint: {fp}')
    return certlist


def get_signature_versions(app_path, tools_dir, signed):
    """Get signature versions using apksigner."""
    v1, v2, v3, v4 = False, False, False, False
    try:
        if not signed:
            return v1, v2, v3, v4
        logger.info('Getting Signature Versions')
        apksigner = Path(tools_dir) / 'apksigner.jar'
        args = [find_java_binary(), '-Xmx1024M',
                '-Djava.library.path=', '-jar',
                apksigner.as_posix(),
                'verify', '--verbose', app_path]
        out = subprocess.check_output(
            args, stderr=subprocess.STDOUT)
        out = out.decode('utf-8', 'ignore')
        if re.findall(r'v1 scheme \(JAR signing\): true', out):
            v1 = True
        if re.findall(r'\(APK Signature Scheme v2\): true', out):
            v2 = True
        if re.findall(r'\(APK Signature Scheme v3\): true', out):
            v3 = True
        if re.findall(r'\(APK Signature Scheme v4\): true', out):
            v4 = True
    except Exception:
        logger.exception('Failed to get signature versions')
    return v1, v2, v3, v4


def apksigtool_cert(apk_path, tools_dir):
    """Get Human readable certificate with apksigtool."""
    certlist = []
    certs = []
    pub_keys = []
    signed = False
    certs_no = 0
    min_sdk = None
    try:
        from apksigtool import (
            APKSignatureSchemeBlock,
            extract_v2_sig,
            parse_apk_signing_block,
        )
        _, sig_block = extract_v2_sig(apk_path)
        for pair in parse_apk_signing_block(sig_block).pairs:
            b = pair.value
            if isinstance(b, APKSignatureSchemeBlock):
                signed = True
                for signer in b.signers:
                    if b.is_v3():
                        min_sdk = signer.min_sdk
                    certs_no = len(signer.signed_data.certificates)
                    for cert in signer.signed_data.certificates:
                        d = get_cert_details(cert.data)
                        for i in d:
                            if i not in certs:
                                certs.append(i)
                    p = get_pub_key_details(signer.public_key.data)
                    for j in p:
                        if j not in pub_keys:
                            pub_keys.append(j)

        if signed:
            certlist.append('Binary is signed')
        else:
            certlist.append('Binary is not signed')
        v1, v2, v3, v4 = get_signature_versions(apk_path, tools_dir, signed)
        certlist.append(f'v1 signature: {v1}')
        certlist.append(f'v2 signature: {v2}')
        certlist.append(f'v3 signature: {v3}')
        certlist.append(f'v4 signature: {v4}')
        certlist.extend(certs)
        certlist.extend(pub_keys)
        certlist.append(f'Found {certs_no} unique certificates')
    except Exception:
        logger.exception('Failed to parse code signing certificate')
        certlist.append('Missing certificate')
    return {
        'cert_data': '\n'.join(certlist),
        'signed': signed,
        'v1': v1,
        'v2': v2,
        'v3': v3,
        'v4': v4,
        'min_sdk': min_sdk,
    }


def get_cert_data(a, app_path, tools_dir):
    """Get Human readable certificate."""
    certlist = []
    signed = False
    if a.is_signed():
        signed = True
        certlist.append('Binary is signed')
    else:
        certlist.append('Binary is not signed')
        certlist.append('Missing certificate')
    v1, v2, v3, v4 = get_signature_versions(app_path, tools_dir, signed)
    certlist.append(f'v1 signature: {v1}')
    certlist.append(f'v2 signature: {v2}')
    certlist.append(f'v3 signature: {v3}')
    certlist.append(f'v4 signature: {v4}')

    certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2()
                + [a.get_certificate_der(x)
                    for x in a.get_signature_names()])
    pkeys = set(a.get_public_keys_der_v3() + a.get_public_keys_der_v2())

    for cert in certs:
        certlist.extend(get_cert_details(cert))

    for public_key in pkeys:
        certlist.extend(get_pub_key_details(public_key))

    if len(certs) > 0:
        certlist.append(f'Found {len(certs)} unique certificates')

    return {
        'cert_data': '\n'.join(certlist),
        'signed': signed,
        'v1': v1,
        'v2': v2,
        'v3': v3,
        'v4': v4,
        'min_sdk': None,
    }


def cert_info(a, app_dic, man_dict):
    """Return certificate information."""
    try:
        logger.info('Reading Code Signing Certificate')
        manifestfile = None
        manidat = ''
        files = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0}

        if a:
            cert_data = get_cert_data(
                a, app_dic['app_path'], app_dic['tools_dir'])
        else:
            logger.warning('androguard certificate parsing failed,'
                           ' switching to apksigtool')
            cert_data = apksigtool_cert(
                app_dic['app_path'], app_dic['tools_dir'])

        cert_path = os.path.join(app_dic['app_dir'], 'META-INF/')
        if os.path.exists(cert_path):
            files = [f for f in os.listdir(
                cert_path) if os.path.isfile(os.path.join(cert_path, f))]
        if 'MANIFEST.MF' in files:
            manifestfile = os.path.join(cert_path, 'MANIFEST.MF')
        if manifestfile:
            with open(manifestfile, 'r', encoding='utf-8') as manifile:
                manidat = manifile.read()
        sha256_digest = bool(re.findall(r'SHA-256-Digest', manidat))
        findings = []
        if cert_data['signed']:
            summary[INFO] += 1
            findings.append((
                INFO,
                'Application is signed with a code '
                'signing certificate',
                'Signed Application'))
        else:
            summary[HIGH] += 1
            findings.append((
                HIGH,
                'Code signing certificate not found',
                'Missing Code Signing certificate'))

        if man_dict['min_sdk']:
            api_level = int(man_dict['min_sdk'])
        elif cert_data['min_sdk']:
            api_level = int(cert_data['min_sdk'])
        else:
            # API Level unknown
            api_level = None

        if cert_data['v1'] and api_level:
            status = HIGH
            summary[HIGH] += 1
            if ((cert_data['v2'] or cert_data['v3'])
                    and api_level < ANDROID_8_1_LEVEL):
                status = WARNING
                summary[HIGH] -= 1
                summary[WARNING] += 1
            findings.append((
                status,
                'Application is signed with v1 signature scheme, '
                'making it vulnerable to Janus vulnerability on '
                'Android 5.0-8.0, if signed only with v1 signature'
                ' scheme. Applications running on Android 5.0-7.0'
                ' signed with v1, and v2/v3 '
                'scheme is also vulnerable.',
                'Application vulnerable to Janus Vulnerability'))
        if re.findall(r'CN=Android Debug', cert_data['cert_data']):
            summary[HIGH] += 1
            findings.append((
                HIGH,
                'Application signed with a debug certificate. '
                'Production application must not be shipped '
                'with a debug certificate.',
                'Application signed with debug certificate'))
        if re.findall(r'Hash Algorithm: sha1', cert_data['cert_data']):
            status = HIGH
            summary[HIGH] += 1
            desc = (
                'Application is signed with SHA1withRSA. '
                'SHA1 hash algorithm is known to have '
                'collision issues.')
            title = 'Certificate algorithm vulnerable to hash collision'
            if sha256_digest:
                status = WARNING
                summary[HIGH] -= 1
                summary[WARNING] += 1
                desc += (
                    ' The manifest file indicates SHA256withRSA'
                    ' is in use.')
                title = ('Certificate algorithm might be '
                         'vulnerable to hash collision')
            findings.append((status, desc, title))
        if re.findall(r'Hash Algorithm: md5', cert_data['cert_data']):
            status = HIGH
            summary[HIGH] += 1
            desc = (
                'Application is signed with MD5. '
                'MD5 hash algorithm is known to have '
                'collision issues.')
            title = 'Certificate algorithm vulnerable to hash collision'
            findings.append((status, desc, title))
        return {
            'certificate_info': cert_data['cert_data'],
            'certificate_findings': findings,
            'certificate_summary': summary,
        }
    except Exception:
        logger.exception('Reading Code Signing Certificate')
        return {}
