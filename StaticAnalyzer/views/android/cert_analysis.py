# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import binascii
import hashlib
import logging
import os
import re

from androguard.core.bytecodes.apk import APK
from androguard.util import get_certificate_name_string

from asn1crypto import keys, x509

from django.utils.html import escape

logger = logging.getLogger(__name__)


def get_hardcoded_cert_keystore(files):
    """Returns the hardcoded certificate keystore."""
    try:
        logger.info('Getting Hardcoded Certificates/Keystores')
        dat = ''
        certz = ''
        key_store = ''
        for file_name in files:
            ext = file_name.split('.')[-1]
            if re.search('cer|pem|cert|crt|pub|key|pfx|p12', ext):
                certz += escape(file_name) + '</br>'
            if re.search('jks|bks', ext):
                key_store += escape(file_name) + '</br>'
        if len(certz) > 1:
            dat += (
                '<tr><td>Certificate/Key Files Hardcoded'
                + ' inside the App.</td><td>'
                + certz
                + '</td><tr>'
            )
        if len(key_store) > 1:
            dat += (
                '<tr><td>Hardcoded Keystore Found.</td><td>'
                + key_store
                + '</td><tr>'
            )
        return dat
    except Exception:
        logger.exception('Getting Hardcoded Certificates/Keystores')


def cert_info(app_dir, app_file, tools_dir):
    """Return certificate information."""
    try:
        logger.info('Reading Code Signing Certificate')
        dat = ''
        manidat = ''
        issued = ''

        dat = androguard_certinfo(app_dir, app_file)

        if re.findall(r'Apk is signed', dat):
            issued = 'good'
        if re.findall(r'Missing certificate', dat):
            issued = 'missing'
        if re.findall(r'CN=Android Debug', dat):
            issued = 'bad'
        if re.findall(r'Hash Algorithm: sha1', dat):
            issued = 'bad hash'
        sha256_digest = bool(re.findall(r'SHA-256-Digest', manidat))
        cert_dic = {
            'cert_info': dat,
            'issued': issued,
            'sha256Digest': sha256_digest,
        }
        return cert_dic
    except Exception:
        logger.exception('Reading Code Signing Certificate')


def androguard_certinfo(app_dir, app_file):
    """Return certificate information."""
    certlist = []
    apk_file = os.path.join(app_dir, app_file)
    hashfunctions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }
    a = APK(apk_file, skip_analysis=True)
    if a.is_signed():
        certlist.append('Apk is signed')
    else:
        certlist.append('Missing certificate')
        return '\n'.join(certlist)

    certlist.append('v1 signature: {}'.format(a.is_signed_v1()))
    certlist.append('v2 signature: {}'.format(a.is_signed_v2()))
    certlist.append('v3 signature: {}'.format(a.is_signed_v3()))

    certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2()
                + [a.get_certificate_der(x) for x in a.get_signature_names()])
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
        x509_public_key = keys.PublicKeyInfo.load(public_key)
        certlist.append('PublicKey Algorithm: {}'.format(
            x509_public_key.algorithm))
        certlist.append('Bit Size: {}'.format(x509_public_key.bit_size))
        certlist.append('Fingerprint: {}'.format(
            binascii.hexlify(x509_public_key.fingerprint).decode('utf-8')))
        try:
            certlist.append('Hash Algorithm: {}'.format(
                x509_public_key.hash_algo))
        except ValueError:
            pass
    return '\n'.join(certlist)
