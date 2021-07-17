# -*- coding: utf_8 -*-
"""Module for network security analysis."""
import logging
from xml.dom import minidom
from pathlib import Path

logger = logging.getLogger(__name__)


def read_netsec_config(app_dir, config, src_type):
    """Read the manifest file."""
    msg = 'Reading Network Security Config'
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
        xmls = Path(xml_dir).glob('*.xml')
        for xml in xmls:
            if xml.stem in [config, 'network_security_config']:
                config_file = xml
                break
        if not config_file:
            return None
        logger.info(msg)
        return config_file.read_text('utf8', 'ignore')
    except Exception:
        logger.exception(msg)
    return None


def analysis(app_dir, config, is_debuggable, src_type):
    """Perform Network Security Analysis."""
    try:
        if not config:
            return []
        netsec_conf = read_netsec_config(app_dir, config, src_type)
        if not netsec_conf:
            return []
        logger.info('Parsing Network Security Config')
        parsed = minidom.parseString(netsec_conf)
        finds = []
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
                    'severity': 'high',
                })
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        'Base config is configured to disallow '
                        'clear text traffic to all domains.'),
                    'severity': 'good',
                })
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
                            'severity': 'info',
                        })
                    elif loc == 'system':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to trust'
                                ' system certificates.'),
                            'severity': 'warning',
                        })
                    elif loc == 'user':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to trust'
                                ' user installed certificates.'),
                            'severity': 'high',
                        })
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Base config is configured to '
                                'bypass certificate pinning.'),
                            'severity': 'high',
                        })
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
                    'severity': 'high',
                })
            elif cfg.getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        'Domain config is securely configured'
                        ' to disallow clear text traffic to these '
                        'domains in scope.'),
                    'severity': 'good',
                })
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
                            'severity': 'info',
                        })
                    elif loc == 'system':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to trust'
                                ' system certificates.'),
                            'severity': 'warning',
                        })
                    elif loc == 'user':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to trust'
                                ' user installed certificates.'),
                            'severity': 'high',
                        })
                    if override == 'true':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                'Domain config is configured to '
                                'bypass certificate pinning.'),
                            'severity': 'high',
                        })
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
                            'pinning will be disabled.'
                            f'[{pins_list}]'),
                        'severity': 'info',
                    })
                else:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            'Certificate pinning does '
                            'not have an expiry. Ensure '
                            'that pins are updated before '
                            'certificate expire.'
                            f'[{pins_list}]'),
                        'severity': 'good',
                    })
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
                    'severity': 'high',
                })
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
                            'severity': 'high',
                        })
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                'Debug override is configured to '
                                'bypass certificate pinning.'),
                            'severity': 'high',
                        })
        return finds
    except Exception:
        logger.exception('Performing Network Security Analysis')
    return []
