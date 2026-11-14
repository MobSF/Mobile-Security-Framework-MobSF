# -*- coding: utf_8 -*-
"""AppxManifest.xml and package signature analysis for APPX/MSIX."""
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import cms

from cryptography import x509

from defusedxml.ElementTree import fromstring

from mobsf.MobSF.security import is_pipe_or_link

logger = logging.getLogger(__name__)

HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 1024 * 1024
P7X_MAGIC = b'PKCX'
FULL_TRUST_ENTRY = 'windows.fulltrustapplication'

# Lowercase capability name mapped to (severity, description).
RESTRICTED_CAPABILITIES = {
    'runfulltrust': (
        HIGH,
        'Runs outside the AppContainer sandbox with the full privileges '
        'of the user. Any vulnerability in the app can be used to access '
        'all of the user\'s data and the system.'),
    'broadfilesystemaccess': (
        HIGH,
        'Grants access to every file the user can access, without a file '
        'picker.'),
    'allowelevation': (
        HIGH,
        'Allows the app to run elevated as administrator.'),
    'packagemanagement': (
        HIGH,
        'Allows installing, updating and removing other packages.'),
    'inputinjectionbrokered': (
        HIGH,
        'Allows the app to inject keyboard, mouse, touch and pen input '
        'into other apps.'),
    'localsystemservices': (
        HIGH,
        'Allows the app to install services that run as LocalSystem.'),
    'unvirtualizedresources': (
        WARNING,
        'Writes to the registry and file system are not virtualized and '
        'persist outside the package after uninstall.'),
    'appdiagnostics': (
        WARNING,
        'Allows reading diagnostic information about other running apps, '
        'such as process and memory details.'),
    'packagequery': (
        WARNING,
        'Allows enumerating other installed packages.'),
    'userdatasystem': (
        WARNING,
        'Allows access to user data across all accounts on the device.'),
    'smssend': (
        WARNING,
        'Allows sending SMS and MMS messages.'),
    'confirmappclose': (
        INFO,
        'Allows the app to delay or prevent being closed.'),
}

GENERAL_CAPABILITIES = {
    'internetclientserver': (
        WARNING,
        'Allows the app to accept inbound connections from the internet, '
        'acting as a server.'),
    'privatenetworkclientserver': (
        WARNING,
        'Allows inbound and outbound connections on home and work '
        'networks, including connections from other devices.'),
    'enterpriseauthentication': (
        WARNING,
        'Allows authenticating to enterprise resources with the user\'s '
        'domain credentials.'),
    'sharedusercertificates': (
        WARNING,
        'Allows access to software and hardware certificates in the '
        'user\'s certificate store.'),
    'documentslibrary': (
        WARNING,
        'Allows access to the user\'s Documents library.'),
    'removablestorage': (
        WARNING,
        'Allows access to files on removable storage such as USB drives.'),
    'useraccountinformation': (
        WARNING,
        'Allows access to the user\'s name and account picture.'),
    'contacts': (WARNING, 'Allows access to the user\'s contacts.'),
    'appointments': (WARNING, 'Allows access to the user\'s calendar.'),
    'phonecall': (WARNING, 'Allows placing phone calls.'),
    'chat': (WARNING, 'Allows reading and sending SMS and MMS messages.'),
    'location': (WARNING, 'Allows access to the device location.'),
    'webcam': (WARNING, 'Allows access to the camera.'),
    'microphone': (WARNING, 'Allows access to the microphone.'),
    'picturelibrary': (INFO, 'Allows access to the Pictures library.'),
    'pictureslibrary': (INFO, 'Allows access to the Pictures library.'),
    'videoslibrary': (INFO, 'Allows access to the Videos library.'),
    'musiclibrary': (INFO, 'Allows access to the Music library.'),
    'internetclient': (INFO, 'Allows outbound internet connections.'),
    'bluetooth': (INFO, 'Allows communication with Bluetooth devices.'),
    'proximity': (INFO, 'Allows near-field proximity communication.'),
}

# Extension category: (severity, title, description)
EXTENSION_RULES = {
    'windows.protocol': (
        WARNING,
        'Custom URI scheme handler',
        'The app registers a custom URI scheme. Any website or app can '
        'launch it with attacker-controlled parameters; validate all '
        'activation arguments.'),
    'windows.fulltrustprocess': (
        WARNING,
        'Full trust process',
        'The package launches a full trust Win32 process that runs '
        'outside the AppContainer sandbox.'),
    'windows.startuptask': (
        INFO,
        'Startup task',
        'The app registers a task that runs when the user signs in.'),
    'windows.comserver': (
        WARNING,
        'Out-of-process COM server',
        'The package registers a COM server that other processes can '
        'activate and call.'),
    'windows.cominterface': (
        WARNING,
        'COM interface registration',
        'The package registers COM interfaces that other processes can '
        'call.'),
    'windows.service': (
        HIGH,
        'Windows service',
        'The package installs a Windows service that runs in the '
        'background with its own account, often with elevated '
        'privileges.'),
    'windows.firewallrules': (
        WARNING,
        'Firewall rules',
        'The package adds Windows Firewall rules, typically to accept '
        'inbound connections.'),
    'windows.appservice': (
        INFO,
        'App service',
        'The app exposes an app service that other apps can call.'),
    'windows.appexecutionalias': (
        INFO,
        'App execution alias',
        'The app registers a command-line alias that can be run from any '
        'console.'),
    'windows.filetypeassociation': (
        INFO,
        'File type association',
        'The app opens files of the listed types. Files from untrusted '
        'sources are parsed by the app.'),
    'windows.loadersearchpathoverride': (
        WARNING,
        'Loader search path override',
        'The package changes the DLL search path, which can enable DLL '
        'planting if the folders are writable.'),
}

BUILD_METADATA = {
    'cl.exe': ('compiler_version', 'Version'),
    'VisualStudio': ('visual_studio_version', 'Version'),
    'VisualStudioEdition': ('visual_studio_edition', 'Value'),
    'OperatingSystem': ('target_os', 'Version'),
    'Microsoft.Build.AppxPackage.dll': ('appx_dll_version', 'Version'),
    'ProjectGUID': ('proj_guid', 'Value'),
    'OptimizingToolset': ('opti_tool', 'Value'),
    'TargetRuntime': ('target_run', 'Value'),
}


def _local(tag):
    return tag.rsplit('}', 1)[-1] if isinstance(tag, str) else ''


def _attr(elem, name):
    """Return an attribute by local name, ignoring its namespace."""
    for key, value in elem.attrib.items():
        if _local(key) == name:
            return value
    return None


def _finding(rule, title, severity, description):
    return {
        'rule': rule,
        'title': title,
        'severity': severity,
        'description': description,
    }


def read_xml(path):
    """Parse an untrusted XML file with size, link and entity limits."""
    path = Path(path)
    if (not path.is_file() or is_pipe_or_link(path)
            or path.stat().st_size > MAX_MANIFEST_BYTES):
        return None
    try:
        return fromstring(path.read_bytes())
    except Exception:
        logger.warning('Failed to parse %s', path.name)
        return None


def empty_manifest():
    return {
        'package_name': '',
        'publisher': '',
        'version': '',
        'arch': '',
        'app_name': '',
        'pub_name': '',
        'description': '',
        'min_os_version': '',
        'executables': [],
        'compiler_version': '',
        'visual_studio_version': '',
        'visual_studio_edition': '',
        'target_os': '',
        'appx_dll_version': '',
        'proj_guid': '',
        'opti_tool': '',
        'target_run': '',
        'capabilities': [],
        'findings': [],
    }


def _parse_identity(root, info):
    for elem in root:
        name = _local(elem.tag)
        if name == 'Identity':
            info['package_name'] = elem.get('Name', '')
            info['publisher'] = elem.get('Publisher', '')
            info['version'] = elem.get('Version', '')
            info['arch'] = elem.get('ProcessorArchitecture', '')
        elif name == 'Properties':
            for sub in elem:
                sub_name = _local(sub.tag)
                if sub_name == 'DisplayName':
                    info['app_name'] = (sub.text or '').strip()
                elif sub_name == 'PublisherDisplayName':
                    info['pub_name'] = (sub.text or '').strip()
                elif sub_name == 'Description':
                    info['description'] = (sub.text or '').strip()
        elif name == 'Metadata':
            for item in elem:
                key = BUILD_METADATA.get(item.get('Name'))
                if key:
                    info[key[0]] = item.get(key[1], '')
    for elem in root.iter():
        name = _local(elem.tag)
        if name == 'TargetDeviceFamily' and not info['min_os_version']:
            info['min_os_version'] = elem.get('MinVersion', '')
        elif name == 'OSMinVersion' and not info['min_os_version']:
            info['min_os_version'] = (elem.text or '').strip()


def _parse_capabilities(root, info):
    for elem in root.iter():
        name = _local(elem.tag)
        if name not in ('Capability', 'DeviceCapability'):
            continue
        cap = elem.get('Name', '')
        if not cap:
            continue
        restricted = 'restrictedcapabilities' in elem.tag.lower()
        key = cap.lower()
        if restricted:
            severity, desc = RESTRICTED_CAPABILITIES.get(
                key,
                (WARNING, 'Restricted capability that requires approval '
                          'for Microsoft Store submission.'))
            kind = 'Restricted'
        elif name == 'DeviceCapability':
            severity, desc = GENERAL_CAPABILITIES.get(
                key, (INFO, 'Access to a device or sensor.'))
            kind = 'Device'
        else:
            severity, desc = GENERAL_CAPABILITIES.get(
                key, (INFO, 'General capability.'))
            kind = 'General'
        info['capabilities'].append({
            'name': cap,
            'type': kind,
            'severity': severity,
            'description': desc,
        })


def _parse_applications(root, info):
    findings = info['findings']
    for app in root.iter():
        if _local(app.tag) != 'Application':
            continue
        app_id = app.get('Id', '')
        exe = app.get('Executable', '')
        if exe:
            info['executables'].append(exe)
        entry = (app.get('EntryPoint') or '').lower()
        trust = (_attr(app, 'TrustLevel') or '').lower()
        behavior = (_attr(app, 'RuntimeBehavior') or '').lower()
        if (entry == FULL_TRUST_ENTRY or trust == 'mediumil'
                or behavior in ('win32app', 'packagedclassicapp')):
            findings.append(_finding(
                'full_trust_application',
                f'Application {app_id} runs with full trust',
                HIGH,
                'The application runs as a full trust (medium integrity) '
                'desktop process instead of inside the AppContainer '
                'sandbox. It has the same access as any program the user '
                'runs.'))
        _parse_content_uri_rules(app, app_id, findings)


def _parse_content_uri_rules(app, app_id, findings):
    for rule in app.iter():
        if _local(rule.tag) != 'Rule':
            continue
        if (rule.get('Type') or '').lower() != 'include':
            continue
        match = rule.get('Match', '')
        winrt = (rule.get('WindowsRuntimeAccess') or '').lower()
        if match.lower().startswith('http://'):
            findings.append(_finding(
                'content_uri_cleartext',
                f'Cleartext content URI allowed in {app_id}',
                HIGH,
                f'ApplicationContentUriRules include {match} over HTTP. '
                'A network attacker can inject script into the app\'s web '
                'content.'))
        if winrt and winrt != 'none':
            findings.append(_finding(
                'content_uri_winrt_access',
                f'Web content has WinRT access in {app_id}',
                WARNING,
                f'Remote content from {match} can call Windows Runtime '
                f'APIs (WindowsRuntimeAccess="{winrt}"). Cross-site '
                'scripting in that content can reach native APIs.'))


def _parse_extensions(root, info):
    findings = info['findings']
    seen = set()
    for ext in root.iter():
        if _local(ext.tag) != 'Extension':
            continue
        category = (ext.get('Category') or '').lower()
        rule = EXTENSION_RULES.get(category)
        if not rule:
            continue
        severity, title, desc = rule
        names = []
        for child in ext.iter():
            child_name = _local(child.tag)
            if child_name in ('Protocol', 'FileTypeAssociation',
                              'AppService', 'ExecutionAlias', 'Service'):
                label = child.get('Name') or child.get('Alias')
                if label:
                    names.append(label)
            if (child_name == 'Service'
                    and (child.get('StartAccount') or '').lower()
                    == 'localsystem'):
                severity = HIGH
                desc += ' This service runs as LocalSystem.'
        detail = f' ({", ".join(sorted(set(names)))})' if names else ''
        key = (category, detail)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_finding(
            category.replace('.', '_'), f'{title}{detail}', severity, desc))


def _parse_dependencies(root, info):
    for elem in root.iter():
        if _local(elem.tag) != 'PackageDependency':
            continue
        name = elem.get('Name', '')
        if name.lower().endswith('.debug'):
            info['findings'].append(_finding(
                'debug_dependency',
                f'Debug runtime dependency ({name})',
                WARNING,
                'The package depends on a debug build of a runtime '
                'library, which indicates a debug build of the app was '
                'packaged. Debug builds include extra diagnostics and are '
                'not meant for distribution.'))


def parse_manifest(manifest_path):
    """Parse AppxManifest.xml into app info, capabilities and findings."""
    info = empty_manifest()
    root = read_xml(manifest_path)
    if root is None:
        return info
    _parse_identity(root, info)
    _parse_capabilities(root, info)
    _parse_applications(root, info)
    _parse_extensions(root, info)
    _parse_dependencies(root, info)
    return info


DN_ALIASES = {
    'S': 'ST',
    'E': '1.2.840.113549.1.9.1',
    'EMAIL': '1.2.840.113549.1.9.1',
    'EMAILADDRESS': '1.2.840.113549.1.9.1',
}
HEX_ESCAPE = re.compile(r'[0-9A-Fa-f]{2}')


def _add_dn_part(parts, key, value):
    key = ''.join(key).strip().upper()
    if key:
        parts.add((DN_ALIASES.get(key, key), ''.join(value).strip()))


def _manifest_dn_parts(dn):
    """Parse a manifest Publisher DN, honouring quotes and escapes."""
    parts = set()
    key, value = [], []
    in_value = quoted = False
    dn = dn or ''
    i = 0
    while i < len(dn):
        ch = dn[i]
        target = value if in_value else key
        if ch == '\\' and i + 1 < len(dn):
            if HEX_ESCAPE.fullmatch(dn[i + 1:i + 3]):
                target.append(chr(int(dn[i + 1:i + 3], 16)))
                i += 3
            else:
                target.append(dn[i + 1])
                i += 2
            continue
        if ch == '"' and in_value:
            quoted = not quoted
        elif ch == '=' and not in_value:
            in_value = True
        elif ch in ',;+' and not quoted:
            _add_dn_part(parts, key, value)
            key, value = [], []
            in_value = False
        else:
            target.append(ch)
        i += 1
    _add_dn_part(parts, key, value)
    return parts


def _cert_dn_parts(name):
    """Attribute set of a certificate subject, matching _manifest_dn_parts."""
    parts = set()
    for attr in name:
        key = attr.rfc4514_attribute_name.upper()
        parts.add((DN_ALIASES.get(key, key), str(attr.value).strip()))
    return parts


def _signer_certificate(raw):
    """Return (certificate, digest algorithm) of the PKCS#7 SignerInfo."""
    info = cms.ContentInfo.load(raw)
    if info['content_type'].native != 'signed_data':
        return None, ''
    signed = info['content']
    signer_infos = signed['signer_infos']
    if not len(signer_infos):
        return None, ''
    signer = signer_infos[0]
    sid = signer['sid']
    for choice in signed['certificates'] or []:
        if choice.name != 'certificate':
            continue
        cert = choice.chosen
        if sid.name == 'issuer_and_serial_number':
            match = (
                cert.issuer == sid.chosen['issuer']
                and cert.serial_number == sid.chosen['serial_number'].native)
        else:
            match = cert.key_identifier == sid.chosen.native
        if match:
            digest = signer['digest_algorithm']['algorithm'].native
            return x509.load_der_x509_certificate(cert.dump()), digest
    return None, ''


def analyze_signature(root_dir, publisher):
    """Inspect AppxSignature.p7x and compare its signer to the publisher."""
    sig_path = Path(root_dir) / 'AppxSignature.p7x'
    result = {
        'signed': False,
        'signer': '',
        'issuer': '',
        'valid_to': '',
        'hash_algorithm': '',
        'findings': [],
    }
    findings = result['findings']
    if (not sig_path.is_file() or is_pipe_or_link(sig_path)
            or sig_path.stat().st_size > MAX_SIGNATURE_BYTES):
        findings.append(_finding(
            'package_unsigned',
            'Package is not signed',
            WARNING,
            'The package has no AppxSignature.p7x. Windows only installs '
            'unsigned packages in developer mode, and its contents cannot '
            'be tied to a publisher.'))
        return result
    raw = sig_path.read_bytes()
    if raw.startswith(P7X_MAGIC):
        raw = raw[len(P7X_MAGIC):]
    try:
        leaf, digest = _signer_certificate(raw)
    except Exception:
        leaf, digest = None, ''
    if not leaf:
        findings.append(_finding(
            'package_signature_invalid',
            'Package signature could not be parsed',
            HIGH,
            'AppxSignature.p7x is present but is not a PKCS#7 signature '
            'with a signer certificate. The package may have been '
            'tampered with.'))
        return result
    result['signed'] = True
    result['signer'] = leaf.subject.rfc4514_string()
    result['issuer'] = leaf.issuer.rfc4514_string()
    result['valid_to'] = leaf.not_valid_after_utc.isoformat()
    result['hash_algorithm'] = digest or ''
    if (publisher
            and _cert_dn_parts(leaf.subject) != _manifest_dn_parts(publisher)):
        findings.append(_finding(
            'package_publisher_mismatch',
            'Signer does not match the manifest publisher',
            HIGH,
            f'The package is signed by "{result["signer"]}" but the '
            f'manifest declares the publisher "{publisher}". Windows '
            'rejects such packages; this indicates a modified or '
            'repackaged app.'))
    if leaf.subject == leaf.issuer:
        findings.append(_finding(
            'package_self_signed',
            'Package is signed with a self-signed certificate',
            WARNING,
            'A self-signed certificate does not prove the publisher\'s '
            'identity. Users must trust the certificate manually to '
            'install the package.'))
    if result['hash_algorithm'] in ('sha1', 'md5'):
        findings.append(_finding(
            'package_weak_signature',
            'Package signature uses a weak hash algorithm',
            WARNING,
            f'The package signature uses {result["hash_algorithm"]}, '
            'which is vulnerable to collision attacks. Use SHA-256.'))
    if leaf.not_valid_after_utc < datetime.now(timezone.utc):
        findings.append(_finding(
            'package_certificate_expired',
            'Signing certificate has expired',
            INFO,
            'The signing certificate has expired. Timestamped packages '
            'remain installable; packages without a timestamp do not.'))
    return result
