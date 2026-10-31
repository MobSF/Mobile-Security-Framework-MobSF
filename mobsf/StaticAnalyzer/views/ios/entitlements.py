# -*- coding: utf_8 -*-
"""iOS Entitlements and Code Signing Security Analysis."""
import logging
import plistlib
import struct
from pathlib import Path

from asn1crypto import cms, x509

import lief

from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import append_scan_status
from mobsf.StaticAnalyzer.views.ios.binary_rule_matcher import (
    _add_bfindings,
)

logger = logging.getLogger(__name__)

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
SKIP_PATH = {'__MACOSX', 'Pods'}
DANGEROUS_BOOL_ENTITLEMENTS = (
    'com.apple.private.security.no-sandbox',
    'com.apple.private.security.no-container',
    'com.apple.security.cs.disable-library-validation',
    'com.apple.security.cs.allow-unsigned-executable-memory',
    'com.apple.security.cs.allow-dyld-environment-variables',
    'com.apple.security.cs.allow-jit',
    'platform-application',
)


def _extract_cms_signer(cms_bytes):
    """Extract the leaf signer human-friendly subject from CMS SignedData."""
    try:
        info = cms.ContentInfo.load(cms_bytes)
        signed_data = info['content']
        certs = [c.chosen for c in signed_data['certificates']]
        for signer_info in signed_data['signer_infos']:
            sid = signer_info['sid']
            if sid.name == 'issuer_and_serial_number':
                ias = sid.chosen
                for cert in certs:
                    if (cert.issuer == ias['issuer']
                            and cert.serial_number == ias['serial_number'].native):
                        return cert.subject.human_friendly
            elif sid.name == 'subject_key_identifier':
                ski = sid.chosen.native
                for cert in certs:
                    if cert.key_identifier == ski:
                        return cert.subject.human_friendly
        for cert in reversed(certs):
            subject = cert.subject.human_friendly
            if ('Apple Root CA' not in subject
                    and 'Certification Authority' not in subject):
                return subject
    except Exception:
        pass
    return ''


def _parse_cs_superblob(raw):
    """Parse Mach-O LC_CODE_SIGNATURE SuperBlob for entitlements and signer."""
    entitlements = {}
    signer = ''
    seen_blobs = set()
    if len(raw) < 12:
        return entitlements, signer
    magic, _, count = struct.unpack('>III', raw[:12])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return entitlements, signer
    max_slots = min(count, (len(raw) - 12) // 8)
    for idx in range(max_slots):
        _, offset = struct.unpack('>II', raw[12 + idx * 8:20 + idx * 8])
        if offset < 0 or offset + 8 > len(raw):
            continue
        blob_magic, blob_len = struct.unpack('>II', raw[offset:offset + 8])
        if (blob_magic not in (
                CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_BLOBWRAPPER)
                or blob_magic in seen_blobs
                or blob_len < 8
                or offset + blob_len > len(raw)):
            continue
        seen_blobs.add(blob_magic)
        payload = raw[offset + 8:offset + blob_len]
        if blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            try:
                loaded = plistlib.loads(payload)
                if isinstance(loaded, dict):
                    entitlements = loaded
            except Exception:
                pass
        elif blob_magic == CSMAGIC_BLOBWRAPPER:
            signer = _extract_cms_signer(payload)
    return entitlements, signer


def extract_macho_entitlements(bin_path):
    """Extract embedded entitlements and signer from a Mach-O binary."""
    if not bin_path:
        return {}, ''
    try:
        fat = lief.MachO.parse(Path(bin_path).as_posix())
        if not fat:
            return {}, ''
        for binary in fat:
            if not binary.has_code_signature:
                continue
            raw = bytes(binary.code_signature.content)
            entitlements, signer = _parse_cs_superblob(raw)
            if entitlements or signer:
                return entitlements, signer
    except Exception:
        logger.warning('Failed to parse Mach-O code signature entitlements')
    return {}, ''


def _parse_mobileprovision_bytes(raw):
    """Parse raw embedded.mobileprovision bytes into a plist dictionary."""
    try:
        info = cms.ContentInfo.load(raw)
        plist_bytes = info['content']['encap_content_info']['content'].native
        if isinstance(plist_bytes, (bytes, bytearray)):
            loaded = plistlib.loads(plist_bytes)
            if isinstance(loaded, dict):
                return loaded
    except Exception:
        pass
    start = raw.find(b'<?xml')
    end = raw.find(b'</plist>')
    if start != -1 and end != -1 and end > start:
        try:
            loaded = plistlib.loads(raw[start:end + len(b'</plist>')])
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass
    return {}


def extract_mobileprovision(dot_app_path):
    """Extract provisioning profile metadata from embedded.mobileprovision."""
    if not dot_app_path:
        return {}
    app_root = Path(dot_app_path)
    prov_path = app_root / 'embedded.mobileprovision'
    if (not is_safe_path(app_root, prov_path, 'embedded.mobileprovision')
            or not prov_path.is_file()
            or is_pipe_or_link(prov_path)):
        return {}
    try:
        plist_obj = _parse_mobileprovision_bytes(prov_path.read_bytes())
    except Exception:
        return {}
    if not plist_obj:
        return {}
    signer = ''
    dev_certs = plist_obj.get('DeveloperCertificates')
    if isinstance(dev_certs, (list, tuple)):
        for cert_der in dev_certs:
            try:
                cert = x509.Certificate.load(cert_der)
                signer = cert.subject.human_friendly
                if signer:
                    break
            except Exception:
                continue
    team_ids = plist_obj.get('TeamIdentifier')
    team_id = (
        team_ids[0]
        if isinstance(team_ids, (list, tuple)) and team_ids
        else ''
    )
    entitlements = plist_obj.get('Entitlements')
    return {
        'entitlements': entitlements if isinstance(entitlements, dict) else {},
        'provisions_all_devices': bool(plist_obj.get('ProvisionsAllDevices')),
        'team_name': str(plist_obj.get('TeamName') or ''),
        'team_id': str(team_id),
        'profile_name': str(plist_obj.get('Name') or ''),
        'signer': signer,
    }


def _check_debuggable_and_dangerous(entitlements, results):
    """Check for debuggable and sandbox-weakening entitlements."""
    if (entitlements.get('get-task-allow') is True
            or entitlements.get('com.apple.security.get-task-allow') is True):
        results.append((
            'ios_entitlement_debuggable',
            'Application is debuggable (get-task-allow enabled)',
            (
                'The application is signed with the get-task-allow entitlement '
                'set to true. This allows attaching a debugger (LLDB/Frida) on '
                'a stock, non-jailbroken iOS device to inspect or modify '
                'runtime memory, bypass security controls, and extract '
                'sensitive data from the application sandbox and Keychain.'
            ),
            {
                'severity': 'high',
                'cvss': 7.5,
                'cwe': 'CWE-489: Active Debug Code',
                'owasp-mobile': 'M8: Code Tampering',
                'masvs': 'MSTG-RESILIENCE-2',
            },
        ))
    dangerous = [
        key for key in DANGEROUS_BOOL_ENTITLEMENTS
        if entitlements.get(key) is True
    ]
    if entitlements.get('com.apple.private.security.container-required') is False:
        dangerous.append('com.apple.private.security.container-required=false')
    if dangerous:
        joined = ', '.join(dangerous)
        results.append((
            'ios_entitlement_dangerous',
            'Application has dangerous or sandbox-weakening entitlements',
            (
                f'The application declares privileged or sandbox-weakening '
                f'entitlements ({joined}). These entitlements weaken iOS '
                f'sandbox isolation, disable dynamic library signature '
                f'validation (enabling dylib injection), or relax code-signing '
                f'memory protections.'
            ),
            {
                'severity': 'high',
                'cvss': 7.8,
                'cwe': 'CWE-250: Execution with Unnecessary Privileges',
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-PLATFORM-1',
            },
        ))


def _check_keychain_and_groups(entitlements, results):
    """Check keychain-access-groups and application-groups."""
    kc_groups = entitlements.get('keychain-access-groups')
    if isinstance(kc_groups, list) and kc_groups:
        str_groups = [str(g) for g in kc_groups if g]
        wildcards = [g for g in str_groups if g == '*' or g.endswith('.*')]
        if wildcards:
            joined = ', '.join(wildcards)
            results.append((
                'ios_keychain_wildcard',
                'Application uses a wildcard Keychain access group',
                (
                    f'The application configures wildcard Keychain access '
                    f'group(s): {joined}. Any application signed with the '
                    f'same Apple Developer Team ID can read and modify '
                    f'Keychain items stored in this shared group.'
                ),
                {
                    'severity': 'warning',
                    'cvss': 5.3,
                    'cwe': 'CWE-522: Insufficiently Protected Credentials',
                    'owasp-mobile': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-1',
                },
            ))
        elif len(str_groups) > 1:
            joined = ', '.join(str_groups)
            results.append((
                'ios_keychain_shared',
                'Application shares Keychain access groups',
                (
                    f'The application configures multiple Keychain access '
                    f'groups ({joined}) to share Keychain items across apps.'
                ),
                {
                    'severity': 'info',
                    'cvss': 0,
                    'cwe': 'CWE-200: Exposure of Sensitive Information',
                    'owasp-mobile': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-1',
                },
            ))
    app_groups = entitlements.get('com.apple.security.application-groups')
    if isinstance(app_groups, list) and app_groups:
        joined = ', '.join(str(g) for g in app_groups if g)
        if joined:
            results.append((
                'ios_app_groups_shared',
                'Application uses shared Application Groups',
                (
                    f'The application is configured with shared Application '
                    f'Group container(s): {joined}. Other applications or app '
                    f'extensions in the same group can access shared '
                    f'NSUserDefaults suites and shared container files.'
                ),
                {
                    'severity': 'info',
                    'cvss': 0,
                    'cwe': 'CWE-200: Exposure of Sensitive Information',
                    'owasp-mobile': 'M2: Insecure Data Storage',
                    'masvs': 'MSTG-STORAGE-2',
                },
            ))


def _check_associated_domains(entitlements, results):
    """Check com.apple.developer.associated-domains."""
    domains = entitlements.get('com.apple.developer.associated-domains')
    if not isinstance(domains, list) or not domains:
        return
    str_domains = [str(d) for d in domains if d]
    if not str_domains:
        return
    joined = ', '.join(str_domains)
    has_risky = any(
        '*' in d or 'mode=developer' in d.lower() for d in str_domains
    )
    if has_risky:
        results.append((
            'ios_associated_domains_wildcard',
            'Application Associated Domains allow wildcard or developer mode',
            (
                f'The application configures Associated Domains with wildcard '
                f'subdomains or developer mode ({joined}). Wildcard patterns '
                f'expand the Universal Links trust boundary across all '
                f'subdomains, and developer mode bypasses Apple CDN validation.'
            ),
            {
                'severity': 'warning',
                'cvss': 4.3,
                'cwe': (
                    'CWE-939: Improper Authorization in Handler for Custom '
                    'URL Scheme'
                ),
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-PLATFORM-3',
            },
        ))
    else:
        results.append((
            'ios_associated_domains',
            'Application configures Associated Domains (Universal Links)',
            f'Configured Associated Domains: {joined}.',
            {
                'severity': 'info',
                'cvss': 0,
                'cwe': (
                    'CWE-939: Improper Authorization in Handler for Custom '
                    'URL Scheme'
                ),
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-PLATFORM-3',
            },
        ))


def evaluate_entitlements(entitlements, profile_info=None):
    """Evaluate security rules on extracted iOS entitlements and profile."""
    results = []
    entitlements = entitlements or {}
    profile_info = profile_info or {}
    _check_debuggable_and_dangerous(entitlements, results)
    if profile_info.get('provisions_all_devices'):
        team = (
            profile_info.get('team_name')
            or profile_info.get('team_id')
            or 'Unknown'
        )
        results.append((
            'ios_enterprise_provisioning',
            'Application is provisioned for Enterprise / All-Devices distribution',
            (
                f'The embedded.mobileprovision profile has '
                f'ProvisionsAllDevices set to true (Team: {team}). This build '
                f'is provisioned with an In-House Enterprise profile allowing '
                f'installation on any iOS device outside App Store review.'
            ),
            {
                'severity': 'warning',
                'cvss': 4.3,
                'cwe': 'CWE-284: Improper Access Control',
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-ARCH-1',
            },
        ))
    _check_keychain_and_groups(entitlements, results)
    _check_associated_domains(entitlements, results)
    return results


def _format_code_signing_info(signer, team_id, team_name, app_id, profile, ents):
    """Format human-readable code signing and entitlements summary."""
    lines = []
    if signer:
        lines.append(f'Signer: {signer}')
    if team_name:
        lines.append(f'Team Name: {team_name}')
    if team_id:
        lines.append(f'Team ID: {team_id}')
    if app_id:
        lines.append(f'Application ID: {app_id}')
    if profile.get('profile_name'):
        lines.append(f"Provisioning Profile: {profile['profile_name']}")
    if ents:
        lines.append('\nEntitlements:')
        for key in sorted(ents.keys()):
            lines.append(f'  {key}: {ents[key]}')
    return '\n'.join(lines)


def ipa_entitlements_analysis(checksum, findings, dot_app_path, bin_path):
    """Run Entitlements and Code Signing analysis on an extracted IPA."""
    try:
        msg = 'Analyzing Mach-O Entitlements and Provisioning Profile'
        logger.info(msg)
        append_scan_status(checksum, msg)
        macho_ents, macho_signer = extract_macho_entitlements(bin_path)
        profile = extract_mobileprovision(dot_app_path)
        prof_ents = profile.get('entitlements') or {}
        effective_ents = dict(macho_ents) if macho_ents else dict(prof_ents)
        for _, title, detailed_desc, rule in evaluate_entitlements(
                effective_ents, profile):
            _add_bfindings(findings, title, detailed_desc, rule)
        signer = macho_signer or profile.get('signer') or ''
        app_id = (
            effective_ents.get('application-identifier')
            or prof_ents.get('application-identifier')
            or ''
        )
        team_id = (
            effective_ents.get('com.apple.developer.team-identifier')
            or profile.get('team_id')
            or ''
        )
        return _format_code_signing_info(
            signer,
            team_id,
            profile.get('team_name', ''),
            app_id,
            profile,
            effective_ents,
        )
    except Exception as exp:
        msg = 'Failed to analyze iOS Entitlements'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return ''


def source_entitlements_analysis(src, code_findings):
    """Scan .entitlements files in an iOS source archive and add findings."""
    root = Path(src)
    for ent_file in root.rglob('*.entitlements'):
        try:
            rel = ent_file.relative_to(root)
            if (not is_safe_path(root, ent_file, rel)
                    or not ent_file.is_file()
                    or is_pipe_or_link(ent_file)
                    or ent_file.name.startswith('._')
                    or any(part in SKIP_PATH for part in rel.parts)):
                continue
            ent_dict = plistlib.loads(ent_file.read_bytes())
            if not isinstance(ent_dict, dict):
                continue
            rel_posix = rel.as_posix()
            for rule_id, title, detailed_desc, rule in evaluate_entitlements(
                    ent_dict):
                desc = f'{title}: {detailed_desc}'
                if rule_id not in code_findings:
                    code_findings[rule_id] = {
                        'files': {},
                        'metadata': {
                            'description': desc,
                            'severity': rule['severity'],
                            'cvss': rule['cvss'],
                            'cwe': rule['cwe'],
                            'owasp-mobile': rule['owasp-mobile'],
                            'masvs': rule['masvs'],
                        },
                    }
                else:
                    existing = code_findings[rule_id]['metadata']['description']
                    if detailed_desc not in existing:
                        code_findings[rule_id]['metadata']['description'] = (
                            f'{existing} {detailed_desc}'
                        )
                code_findings[rule_id]['files'][rel_posix] = '1'
        except Exception:
            logger.warning('Failed to parse source entitlements file')
