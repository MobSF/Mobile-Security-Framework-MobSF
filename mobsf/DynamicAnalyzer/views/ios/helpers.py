# -*- coding: utf_8 -*-
"""iOS helpers."""
import logging
from threading import Thread
from pathlib import Path

from django.conf import settings

from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    start_proxy,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    get_md5,
    python_dict,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_ssh import (
    ssh_jumphost_reverse_port_forward,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS


logger = logging.getLogger(__name__)


def get_local_ipa_list():
    """Get local ipa list."""
    scan_apps = []
    ipas = StaticAnalyzerIOS.objects.filter(
        FILE_NAME__endswith='.ipa')
    for ipa in reversed(ipas):
        bundle_hash = get_md5(ipa.BUNDLE_ID.encode('utf-8'))
        frida_dump = Path(
            settings.UPLD_DIR) / bundle_hash / 'mobsf_dump_file.txt'
        macho = python_dict(ipa.MACHO_ANALYSIS)
        encrypted = False
        if (macho
                and macho.get('encrypted')
                and macho.get('encrypted').get('is_encrypted')):
            encrypted = macho['encrypted']['is_encrypted']
        temp_dict = {
            'MD5': ipa.MD5,
            'APP_NAME': ipa.APP_NAME,
            'APP_VERSION': ipa.APP_VERSION,
            'FILE_NAME': ipa.FILE_NAME,
            'BUNDLE_ID': ipa.BUNDLE_ID,
            'BUNDLE_HASH': bundle_hash,
            'ENCRYPTED': encrypted,
            'DYNAMIC_REPORT_EXISTS': frida_dump.exists(),
        }
        scan_apps.append(temp_dict)
    return scan_apps


def get_ios_model_mapping():
    """Get iOS model mapping."""
    return {
        # iPhone Simulator
        'i386': 'iPhone Simulator',
        'x86_64': 'iPhone Simulator',
        'arm64': 'iPhone Simulator',
        
        # iPhone Models
        'iPhone1,1': 'iPhone',
        'iPhone1,2': 'iPhone 3G',
        'iPhone2,1': 'iPhone 3GS',
        'iPhone3,1': 'iPhone 4',
        'iPhone3,2': 'iPhone 4 GSM Rev A',
        'iPhone3,3': 'iPhone 4 CDMA',
        'iPhone4,1': 'iPhone 4S',
        'iPhone5,1': 'iPhone 5 (GSM)',
        'iPhone5,2': 'iPhone 5 (GSM+CDMA)',
        'iPhone5,3': 'iPhone 5C (GSM)',
        'iPhone5,4': 'iPhone 5C (Global)',
        'iPhone6,1': 'iPhone 5S (GSM)',
        'iPhone6,2': 'iPhone 5S (Global)',
        'iPhone7,1': 'iPhone 6 Plus',
        'iPhone7,2': 'iPhone 6',
        'iPhone8,1': 'iPhone 6s',
        'iPhone8,2': 'iPhone 6s Plus',
        'iPhone8,4': 'iPhone SE (GSM)',
        'iPhone9,1': 'iPhone 7',
        'iPhone9,2': 'iPhone 7 Plus',
        'iPhone9,3': 'iPhone 7',
        'iPhone9,4': 'iPhone 7 Plus',
        'iPhone10,1': 'iPhone 8',
        'iPhone10,2': 'iPhone 8 Plus',
        'iPhone10,3': 'iPhone X Global',
        'iPhone10,4': 'iPhone 8',
        'iPhone10,5': 'iPhone 8 Plus',
        'iPhone10,6': 'iPhone X GSM',
        'iPhone11,2': 'iPhone XS',
        'iPhone11,4': 'iPhone XS Max',
        'iPhone11,6': 'iPhone XS Max Global',
        'iPhone11,8': 'iPhone XR',
        'iPhone12,1': 'iPhone 11',
        'iPhone12,3': 'iPhone 11 Pro',
        'iPhone12,5': 'iPhone 11 Pro Max',
        'iPhone12,8': 'iPhone SE 2nd Gen',
        'iPhone13,1': 'iPhone 12 Mini',
        'iPhone13,2': 'iPhone 12',
        'iPhone13,3': 'iPhone 12 Pro',
        'iPhone13,4': 'iPhone 12 Pro Max',
        'iPhone14,2': 'iPhone 13 Pro',
        'iPhone14,3': 'iPhone 13 Pro Max',
        'iPhone14,4': 'iPhone 13 Mini',
        'iPhone14,5': 'iPhone 13',
        'iPhone14,6': 'iPhone SE 3rd Gen',
        'iPhone14,7': 'iPhone 14',
        'iPhone14,8': 'iPhone 14 Plus',
        'iPhone15,2': 'iPhone 14 Pro',
        'iPhone15,3': 'iPhone 14 Pro Max',
        'iPhone15,4': 'iPhone 15',
        'iPhone15,5': 'iPhone 15 Plus',
        'iPhone16,1': 'iPhone 15 Pro',
        'iPhone16,2': 'iPhone 15 Pro Max',
        'iPhone17,1': 'iPhone 16 Pro',
        'iPhone17,2': 'iPhone 16 Pro Max',
        'iPhone17,3': 'iPhone 16',
        'iPhone17,4': 'iPhone 16 Plus',
        'iPhone17,5': 'iPhone 16e',
        
        # iPod Models
        'iPod1,1': '1st Gen iPod',
        'iPod2,1': '2nd Gen iPod',
        'iPod3,1': '3rd Gen iPod',
        'iPod4,1': '4th Gen iPod',
        'iPod5,1': '5th Gen iPod',
        'iPod7,1': '6th Gen iPod',
        'iPod9,1': '7th Gen iPod',
        
        # iPad Models
        'iPad1,1': 'iPad',
        'iPad1,2': 'iPad 3G',
        'iPad2,1': '2nd Gen iPad',
        'iPad2,2': '2nd Gen iPad GSM',
        'iPad2,3': '2nd Gen iPad CDMA',
        'iPad2,4': '2nd Gen iPad New Revision',
        'iPad3,1': '3rd Gen iPad',
        'iPad3,2': '3rd Gen iPad CDMA',
        'iPad3,3': '3rd Gen iPad GSM',
        'iPad2,5': 'iPad mini',
        'iPad2,6': 'iPad mini GSM+LTE',
        'iPad2,7': 'iPad mini CDMA+LTE',
        'iPad3,4': '4th Gen iPad',
        'iPad3,5': '4th Gen iPad GSM+LTE',
        'iPad3,6': '4th Gen iPad CDMA+LTE',
        'iPad4,1': 'iPad Air (WiFi)',
        'iPad4,2': 'iPad Air (GSM+CDMA)',
        'iPad4,3': '1st Gen iPad Air (China)',
        'iPad4,4': 'iPad mini Retina (WiFi)',
        'iPad4,5': 'iPad mini Retina (GSM+CDMA)',
        'iPad4,6': 'iPad mini Retina (China)',
        'iPad4,7': 'iPad mini 3 (WiFi)',
        'iPad4,8': 'iPad mini 3 (GSM+CDMA)',
        'iPad4,9': 'iPad Mini 3 (China)',
        'iPad5,1': 'iPad mini 4 (WiFi)',
        'iPad5,2': '4th Gen iPad mini (WiFi+Cellular)',
        'iPad5,3': 'iPad Air 2 (WiFi)',
        'iPad5,4': 'iPad Air 2 (Cellular)',
        'iPad6,3': 'iPad Pro (9.7 inch, WiFi)',
        'iPad6,4': 'iPad Pro (9.7 inch, WiFi+LTE)',
        'iPad6,7': 'iPad Pro (12.9 inch, WiFi)',
        'iPad6,8': 'iPad Pro (12.9 inch, WiFi+LTE)',
        'iPad6,11': 'iPad (2017)',
        'iPad6,12': 'iPad (2017)',
        'iPad7,1': 'iPad Pro 2nd Gen (WiFi)',
        'iPad7,2': 'iPad Pro 2nd Gen (WiFi+Cellular)',
        'iPad7,3': 'iPad Pro 10.5-inch 2nd Gen',
        'iPad7,4': 'iPad Pro 10.5-inch 2nd Gen',
        'iPad7,5': 'iPad 6th Gen (WiFi)',
        'iPad7,6': 'iPad 6th Gen (WiFi+Cellular)',
        'iPad7,11': 'iPad 7th Gen 10.2-inch (WiFi)',
        'iPad7,12': 'iPad 7th Gen 10.2-inch (WiFi+Cellular)',
        'iPad8,1': 'iPad Pro 11 inch 3rd Gen (WiFi)',
        'iPad8,2': 'iPad Pro 11 inch 3rd Gen (1TB, WiFi)',
        'iPad8,3': 'iPad Pro 11 inch 3rd Gen (WiFi+Cellular)',
        'iPad8,4': 'iPad Pro 11 inch 3rd Gen (1TB, WiFi+Cellular)',
        'iPad8,5': 'iPad Pro 12.9 inch 3rd Gen (WiFi)',
        'iPad8,6': 'iPad Pro 12.9 inch 3rd Gen (1TB, WiFi)',
        'iPad8,7': 'iPad Pro 12.9 inch 3rd Gen (WiFi+Cellular)',
        'iPad8,8': 'iPad Pro 12.9 inch 3rd Gen (1TB, WiFi+Cellular)',
        'iPad8,9': 'iPad Pro 11 inch 4th Gen (WiFi)',
        'iPad8,10': 'iPad Pro 11 inch 4th Gen (WiFi+Cellular)',
        'iPad8,11': 'iPad Pro 12.9 inch 4th Gen (WiFi)',
        'iPad8,12': 'iPad Pro 12.9 inch 4th Gen (WiFi+Cellular)',
        'iPad11,1': 'iPad mini 5th Gen (WiFi)',
        'iPad11,2': 'iPad mini 5th Gen',
        'iPad11,3': 'iPad Air 3rd Gen (WiFi)',
        'iPad11,4': 'iPad Air 3rd Gen',
        'iPad11,6': 'iPad 8th Gen (WiFi)',
        'iPad11,7': 'iPad 8th Gen (WiFi+Cellular)',
        'iPad12,1': 'iPad 9th Gen (WiFi)',
        'iPad12,2': 'iPad 9th Gen (WiFi+Cellular)',
        'iPad14,1': 'iPad mini 6th Gen (WiFi)',
        'iPad14,2': 'iPad mini 6th Gen (WiFi+Cellular)',
        'iPad13,1': 'iPad Air 4th Gen (WiFi)',
        'iPad13,2': 'iPad Air 4th Gen (WiFi+Cellular)',
        'iPad13,4': 'iPad Pro 11 inch 5th Gen',
        'iPad13,5': 'iPad Pro 11 inch 5th Gen',
        'iPad13,6': 'iPad Pro 11 inch 5th Gen',
        'iPad13,7': 'iPad Pro 11 inch 5th Gen',
        'iPad13,8': 'iPad Pro 12.9 inch 5th Gen',
        'iPad13,9': 'iPad Pro 12.9 inch 5th Gen',
        'iPad13,10': 'iPad Pro 12.9 inch 5th Gen',
        'iPad13,11': 'iPad Pro 12.9 inch 5th Gen',
        'iPad13,16': 'iPad Air 5th Gen (WiFi)',
        'iPad13,17': 'iPad Air 5th Gen (WiFi+Cellular)',
        'iPad13,18': 'iPad 10th Gen',
        'iPad13,19': 'iPad 10th Gen',
        'iPad14,3': 'iPad Pro 11 inch 4th Gen',
        'iPad14,4': 'iPad Pro 11 inch 4th Gen',
        'iPad14,5': 'iPad Pro 12.9 inch 6th Gen',
        'iPad14,6': 'iPad Pro 12.9 inch 6th Gen',
        'iPad14,8': 'iPad Air 11 inch 6th Gen (WiFi)',
        'iPad14,9': 'iPad Air 11 inch 6th Gen (WiFi+Cellular)',
        'iPad14,10': 'iPad Air 13 inch 6th Gen (WiFi)',
        'iPad14,11': 'iPad Air 13 inch 6th Gen (WiFi+Cellular)',
        'iPad15,3': 'iPad Air 11-inch 7th Gen (WiFi)',
        'iPad15,4': 'iPad Air 11-inch 7th Gen (WiFi+Cellular)',
        'iPad15,5': 'iPad Air 13-inch 7th Gen (WiFi)',
        'iPad15,6': 'iPad Air 13-inch 7th Gen (WiFi+Cellular)',
        'iPad15,7': 'iPad 11th Gen (WiFi)',
        'iPad15,8': 'iPad 11th Gen (WiFi+Cellular)',
        'iPad16,1': 'iPad mini 7th Gen (WiFi)',
        'iPad16,2': 'iPad mini 7th Gen (WiFi+Cellular)',
        'iPad16,3': 'iPad Pro 11 inch 5th Gen',
        'iPad16,4': 'iPad Pro 11 inch 5th Gen',
        'iPad16,5': 'iPad Pro 12.9 inch 7th Gen',
        'iPad16,6': 'iPad Pro 12.9 inch 7th Gen',
        
        # Apple Watch Models
        'Watch1,1': 'Apple Watch 38mm case',
        'Watch1,2': 'Apple Watch 42mm case',
        'Watch2,6': 'Apple Watch Series 1 38mm case',
        'Watch2,7': 'Apple Watch Series 1 42mm case',
        'Watch2,3': 'Apple Watch Series 2 38mm case',
        'Watch2,4': 'Apple Watch Series 2 42mm case',
        'Watch3,1': 'Apple Watch Series 3 38mm case (GPS+Cellular)',
        'Watch3,2': 'Apple Watch Series 3 42mm case (GPS+Cellular)',
        'Watch3,3': 'Apple Watch Series 3 38mm case (GPS)',
        'Watch3,4': 'Apple Watch Series 3 42mm case (GPS)',
        'Watch4,1': 'Apple Watch Series 4 40mm case (GPS)',
        'Watch4,2': 'Apple Watch Series 4 44mm case (GPS)',
        'Watch4,3': 'Apple Watch Series 4 40mm case (GPS+Cellular)',
        'Watch4,4': 'Apple Watch Series 4 44mm case (GPS+Cellular)',
        'Watch5,1': 'Apple Watch Series 5 40mm case (GPS)',
        'Watch5,2': 'Apple Watch Series 5 44mm case (GPS)',
        'Watch5,3': 'Apple Watch Series 5 40mm case (GPS+Cellular)',
        'Watch5,4': 'Apple Watch Series 5 44mm case (GPS+Cellular)',
        'Watch5,9': 'Apple Watch SE 40mm case (GPS)',
        'Watch5,10': 'Apple Watch SE 44mm case (GPS)',
        'Watch5,11': 'Apple Watch SE 40mm case (GPS+Cellular)',
        'Watch5,12': 'Apple Watch SE 44mm case (GPS+Cellular)',
        'Watch6,1': 'Apple Watch Series 6 40mm case (GPS)',
        'Watch6,2': 'Apple Watch Series 6 44mm case (GPS)',
        'Watch6,3': 'Apple Watch Series 6 40mm case (GPS+Cellular)',
        'Watch6,4': 'Apple Watch Series 6 44mm case (GPS+Cellular)',
        'Watch6,6': 'Apple Watch Series 7 41mm case (GPS)',
        'Watch6,7': 'Apple Watch Series 7 45mm case (GPS)',
        'Watch6,8': 'Apple Watch Series 7 41mm case (GPS+Cellular)',
        'Watch6,9': 'Apple Watch Series 7 45mm case (GPS+Cellular)',
        'Watch6,10': 'Apple Watch SE 40mm case (GPS)',
        'Watch6,11': 'Apple Watch SE 44mm case (GPS)',
        'Watch6,12': 'Apple Watch SE 40mm case (GPS+Cellular)',
        'Watch6,13': 'Apple Watch SE 44mm case (GPS+Cellular)',
        'Watch6,14': 'Apple Watch Series 8 41mm case (GPS)',
        'Watch6,15': 'Apple Watch Series 8 45mm case (GPS)',
        'Watch6,16': 'Apple Watch Series 8 41mm case (GPS+Cellular)',
        'Watch6,17': 'Apple Watch Series 8 45mm case (GPS+Cellular)',
        'Watch6,18': 'Apple Watch Ultra',
        'Watch7,1': 'Apple Watch Series 9 41mm case (GPS)',
        'Watch7,2': 'Apple Watch Series 9 45mm case (GPS)',
        'Watch7,3': 'Apple Watch Series 9 41mm case (GPS+Cellular)',
        'Watch7,4': 'Apple Watch Series 9 45mm case (GPS+Cellular)',
        'Watch7,5': 'Apple Watch Ultra 2',
        'Watch7,8': 'Apple Watch Series 10 42mm case (GPS)',
        'Watch7,9': 'Apple Watch Series 10 46mm case (GPS)',
        'Watch7,10': 'Apple Watch Series 10 42mm case (GPS+Cellular)',
        'Watch7,11': 'Apple Watch Series 10 46mm (GPS+Cellular)',
    }

def configure_proxy(request, project, ci=None):
    """Configure HTTPS Proxy."""
    proxy_port = settings.PROXY_PORT
    logger.info('Starting HTTPS Proxy on %s', proxy_port)
    stop_httptools(get_http_tools_url(request))
    start_proxy(proxy_port, project)
    if ci:
        # Remote Port forward for HTTPS Proxy
        logger.info('Starting Remote Port Forward over SSH')
        Thread(target=ssh_jumphost_reverse_port_forward,
            args=(ci.get_ssh_connection_string(),),
            daemon=True).start()
