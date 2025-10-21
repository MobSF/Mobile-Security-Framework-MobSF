# -*- coding: utf_8 -*-
"""Module for network security analysis."""
import logging
from xml.dom import minidom
from pathlib import Path

from mobsf.MobSF.utils import (
    append_scan_status,
    is_path_traversal,
)

logger = logging.getLogger(__name__)
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'


def read_netsec_config(checksum, app_dir, config, src_type):
    """Read the manifest file."""
    msg = 'Reading Network Security config'
    try:
        config_file = None
        config = config.replace('@xml/', '', 1)
        base = Path(app_dir)
        if src_type:
            # Support only android studio source files
            xml_dir = base / 'app' / 'src' / 'main' / 'res' / 'xml'
        else:
            # APK
            xml_dir = base / 'apktool_out' / 'res' / 'xml'
        if not is_path_traversal(config):
            netsec_file = xml_dir / f'{config}.xml'
            if netsec_file.exists():
                desc = f'{msg} from {config}.xml'
                logger.info(desc)
                append_scan_status(checksum, desc)
                return netsec_file.read_text('utf8', 'ignore')
        # Couldn't find the file defined in manifest
        xmls = Path(xml_dir).glob('*.xml')
        for xml in xmls:
            if 'network_security' in xml.stem:
                config_file = xml
                break
        if not config_file:
            return None
        desc = f'{msg} from {config_file.name}'
        logger.info(desc)
        append_scan_status(checksum, desc)
        return config_file.read_text('utf8', 'ignore')
    except Exception as exp:
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return None


def analysis(checksum, app_dir, config, is_debuggable, src_type):
    """Perform Network Security Analysis."""
    try:
        netsec = {
            'network_findings': [],
            'network_summary': {},
        }
        if not config:
            return netsec
        netsec_conf = read_netsec_config(
            checksum,
            app_dir,
            config,
            src_type)
        if not netsec_conf:
            return netsec
        msg = 'Parsing Network Security config'
        logger.info(msg)
        append_scan_status(checksum, msg)
        parsed = minidom.parseString(netsec_conf)
        finds = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0, SECURE: 0}
        # Base Config
        b_cfg = parsed.getElementsByTagName('base-config')
        # 0 or 1 of <base-config>
        if b_cfg:
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        'Base config is insecurely configured'
                        ' to permit clear text traffic to all domains.'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        'Base config is configured to disallow '
                        'clear text traffic to all domains.'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            trst_anch = b_cfg[0].getElementsByTagName('trust-anchors')
            if trst_anch:
                certs = trst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to trust'
                                f'bundled certs {loc}.'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to trust'
                                ' system certificates.'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to trust'
                                ' user installed certificates.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to '
                                'bypass certificate pinning.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        # Domain Config
        dom_cfg = parsed.getElementsByTagName('domain-config')
        # Any number of <domain-config>
        for cfg in dom_cfg:
            domain_list = []
            domains = cfg.getElementsByTagName('domain')
            for dom in domains:
                domain_list.append(dom.firstChild.nodeValue)
            if cfg.getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        'Domain config is insecurely configured'
                        ' to permit clear text traffic to these '
                        'domains in scope.'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            elif cfg.getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        'Domain config is securely configured'
                        ' to disallow clear text traffic to these '
                        'domains in scope.'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            dtrust = cfg.getElementsByTagName('trust-anchors')
            if dtrust:
                certs = dtrust[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to trust '
                                f'bundled certs {loc}.'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to trust'
                                ' system certificates.'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to trust'
                                ' user installed certificates.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to '
                                'bypass certificate pinning.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
            pinsets = cfg.getElementsByTagName('pin-set')
            if pinsets:
                exp = pinsets[0].getAttribute('expiration')
                pins = pinsets[0].getElementsByTagName('pin')
                all_pins = []
                for pin in pins:
                    digest = pin.getAttribute('digest')
                    pin_val = pin.firstChild.nodeValue
                    if digest:
                        tmp = f'Pin: {pin_val} Digest: {digest}'
                    else:
                        tmp = f'Pin: {pin_val}'
                    all_pins.append(tmp)
                pins_list = ','.join(all_pins)
                if exp:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            'Certificate pinning expires '
                            f'on {exp}. After this date '
                            'pinning will be disabled. '
                            f'[{pins_list}]'),
                        'severity': INFO,
                    })
                    summary[INFO] += 1
                else:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            'Certificate pinning does '
                            'not have an expiry. Ensure '
                            'that pins are updated before '
                            'certificate expire. '
                            f'[{pins_list}]'),
                        'severity': SECURE,
                    })
                    summary[SECURE] += 1
        # Debug Overrides
        de_over = parsed.getElementsByTagName('debug-overrides')
        # 0 or 1 of <debug-overrides>
        if de_over and is_debuggable:
            if de_over[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        'Debug override is configured to permit clear '
                        'text traffic to all domains and the app '
                        'is debuggable.'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            otrst_anch = de_over[0].getElementsByTagName('trust-anchors')
            if otrst_anch:
                certs = otrst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Debug override is configured to trust '
                                f'bundled debug certs {loc}.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Debug override is configured to '
                                'bypass certificate pinning.'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        netsec['network_findings'] = finds
        netsec['network_summary'] = summary
    except Exception as exp:
        msg = 'Performing Network Security Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return netsec
