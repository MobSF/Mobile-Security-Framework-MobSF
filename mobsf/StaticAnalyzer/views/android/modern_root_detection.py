# -*- coding: utf_8 -*-
"""Modern Root Detection Analysis for Android Apps.

This module provides detection capabilities for modern rooting methods
including Magisk, KernelSU, APatch, and Zygisk framework.
"""
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Modern root packages (2024+)
MODERN_ROOT_PACKAGES = {
    'magisk': [
        'com.topjohnwu.magisk',
        'io.github.huskydg.magisk',
        'com.topjohnwu.magisk.canary',
    ],
    'kernelsu': [
        'me.weishu.kernelsu',
    ],
    'apatch': [
        'io.github.apatch',
        'me.tool.passkey',
    ],
    'legacy': [
        'eu.chainfire.supersu',
        'eu.chainfire.supersu.pro',
        'com.koushikdutta.superuser',
        'com.noshufou.android.su',
    ],
}

# Modern root paths and mount points
MODERN_ROOT_PATHS = [
    # Magisk
    '/data/adb/magisk',
    '/data/adb/modules',
    '/data/adb/post-fs-data.d',
    '/data/adb/service.d',
    '/sbin/.magisk',
    '/cache/.magisk',
    '/metadata/.magisk',
    '/persist/.magisk',
    '/dev/magisk/mirror',
    '/system/bin/resetprop',

    # KernelSU
    '/data/adb/ksu',
    '/data/adb/ksud',

    # APatch
    '/data/adb/ap',
    '/data/adb/apd',

    # Legacy
    '/sbin/su',
    '/system/bin/su',
    '/system/xbin/su',
    '/data/local/xbin/su',
    '/data/local/bin/su',
    '/system/sd/xbin/su',
    '/system/bin/failsafe/su',
    '/data/local/su',
    '/su/bin/su',
]

# Modern root binaries
MODERN_ROOT_BINARIES = [
    'magisk',
    'magisk32',
    'magisk64',
    'magiskhide',
    'magiskpolicy',
    'magiskinit',
    'magiskboot',
    'resetprop',
    'su',
    'busybox',
    'ksud',
    'apd',
]

# Native libraries that may indicate root detection or bypass
ROOT_DETECTION_LIBS = [
    'librootbeer',
    'libmagisk',
    'libsafetynet',
    'libintegrity',
    'librootcheck',
    'libantihook',
]

# Suspicious build properties
SUSPICIOUS_PROPERTIES = [
    'ro.build.tags=test-keys',
    'ro.debuggable=1',
    'ro.secure=0',
    'ro.boot.verifiedbootstate=orange',
    'ro.boot.flash.locked=0',
]


def detect_root_packages(decoded_dir: Path) -> dict:
    """Detect modern root management packages in decompiled APK.

    Args:
        decoded_dir: Path to decoded/decompiled APK directory

    Returns:
        dict: Detection results with package names and evidence
    """
    results = {
        'found': False,
        'packages': [],
        'evidence': [],
    }

    try:
        # Search for package references in code
        java_files = list(decoded_dir.rglob('*.java'))
        smali_files = list(decoded_dir.rglob('*.smali'))

        for file_path in java_files + smali_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')

                # Check for root package references
                for root_type, packages in MODERN_ROOT_PACKAGES.items():
                    for package in packages:
                        if package in content:
                            results['found'] = True
                            if package not in results['packages']:
                                results['packages'].append(package)
                                results['evidence'].append({
                                    'type': root_type,
                                    'package': package,
                                    'file': str(file_path.relative_to(decoded_dir)),
                                })
            except Exception as e:
                logger.debug(f'Error reading {file_path}: {e}')
                continue

    except Exception as e:
        logger.error(f'Error detecting root packages: {e}')

    return results


def detect_root_strings(decoded_dir: Path) -> dict:
    """Detect hardcoded root paths and binaries in strings.

    Args:
        decoded_dir: Path to decoded/decompiled APK directory

    Returns:
        dict: Detection results with paths and binaries found
    """
    results = {
        'found': False,
        'paths': [],
        'binaries': [],
        'properties': [],
    }

    try:
        # Check strings.xml and other resource files
        resource_files = list(decoded_dir.rglob('*.xml'))
        resource_files.extend(decoded_dir.rglob('*.txt'))

        for file_path in resource_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')

                # Check for root paths
                for path in MODERN_ROOT_PATHS:
                    if path in content:
                        results['found'] = True
                        if path not in results['paths']:
                            results['paths'].append(path)

                # Check for root binaries
                for binary in MODERN_ROOT_BINARIES:
                    # Use word boundary to avoid false positives
                    if re.search(rf'\b{re.escape(binary)}\b', content):
                        results['found'] = True
                        if binary not in results['binaries']:
                            results['binaries'].append(binary)

                # Check for suspicious build properties
                for prop in SUSPICIOUS_PROPERTIES:
                    if prop in content:
                        results['found'] = True
                        if prop not in results['properties']:
                            results['properties'].append(prop)

            except Exception as e:
                logger.debug(f'Error reading {file_path}: {e}')
                continue

    except Exception as e:
        logger.error(f'Error detecting root strings: {e}')

    return results


def detect_root_detection_libraries(decoded_dir: Path) -> dict:
    """Detect root detection/bypass libraries in native code.

    Args:
        decoded_dir: Path to decoded/decompiled APK directory

    Returns:
        dict: Detection results with libraries found
    """
    results = {
        'found': False,
        'libraries': [],
    }

    try:
        # Check lib directories for suspicious .so files
        lib_dirs = list(decoded_dir.rglob('lib'))

        for lib_dir in lib_dirs:
            if lib_dir.is_dir():
                so_files = list(lib_dir.rglob('*.so'))

                for so_file in so_files:
                    so_name = so_file.stem.lower()

                    for suspicious_lib in ROOT_DETECTION_LIBS:
                        if suspicious_lib in so_name:
                            results['found'] = True
                            lib_info = {
                                'name': so_file.name,
                                'path': str(so_file.relative_to(decoded_dir)),
                                'type': suspicious_lib,
                            }
                            if lib_info not in results['libraries']:
                                results['libraries'].append(lib_info)

    except Exception as e:
        logger.error(f'Error detecting root detection libraries: {e}')

    return results


def analyze_modern_root_detection(app_dir: str) -> dict:
    """Comprehensive modern root detection analysis.

    Args:
        app_dir: Path to app directory (decoded APK)

    Returns:
        dict: Complete analysis results
    """
    app_path = Path(app_dir)

    analysis = {
        'has_root_detection': False,
        'root_packages': {},
        'root_strings': {},
        'root_libraries': {},
        'risk_level': 'low',
        'recommendations': [],
    }

    try:
        # Detect root packages
        pkg_results = detect_root_packages(app_path)
        if pkg_results['found']:
            analysis['has_root_detection'] = True
            analysis['root_packages'] = pkg_results

        # Detect root strings
        str_results = detect_root_strings(app_path)
        if str_results['found']:
            analysis['has_root_detection'] = True
            analysis['root_strings'] = str_results

        # Detect root detection libraries
        lib_results = detect_root_detection_libraries(app_path)
        if lib_results['found']:
            analysis['has_root_detection'] = True
            analysis['root_libraries'] = lib_results

        # Determine risk level
        if analysis['has_root_detection']:
            evidence_count = (
                len(pkg_results.get('packages', [])) +
                len(str_results.get('paths', [])) +
                len(lib_results.get('libraries', []))
            )

            if evidence_count > 10:
                analysis['risk_level'] = 'high'
            elif evidence_count > 5:
                analysis['risk_level'] = 'medium'
            else:
                analysis['risk_level'] = 'low'

        # Generate recommendations
        if pkg_results.get('packages'):
            magisk_found = any('magisk' in p for p in pkg_results['packages'])
            kernelsu_found = any('kernelsu' in p for p in pkg_results['packages'])
            apatch_found = any('apatch' in p for p in pkg_results['packages'])

            if magisk_found:
                analysis['recommendations'].append(
                    'App checks for Magisk. Consider using Magisk Hide or Zygisk DenyList for testing.')
            if kernelsu_found:
                analysis['recommendations'].append(
                    'App checks for KernelSU. Use KernelSU hide features during security testing.')
            if apatch_found:
                analysis['recommendations'].append(
                    'App checks for APatch. Enable APatch hiding capabilities.')

        if str_results.get('paths'):
            analysis['recommendations'].append(
                'App performs file-based root detection. Use mount namespace isolation.')

        if lib_results.get('libraries'):
            analysis['recommendations'].append(
                'App uses native root detection. Frida may be required to bypass checks.')

    except Exception as e:
        logger.exception('Error in modern root detection analysis')
        analysis['error'] = str(e)

    return analysis
