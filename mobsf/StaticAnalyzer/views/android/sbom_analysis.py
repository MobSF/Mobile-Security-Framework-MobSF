# -*- coding: utf_8 -*-
"""Extract packages from APK."""
import logging

from mobsf.MobSF.utils import (
    PKG_REGEX,
)
from mobsf.StaticAnalyzer.views.common.sbom import (
    check_osv_vulnerabilities,
    extract_android_components,
)


logger = logging.getLogger(__name__)


def merge_common_packages(items):
    """Merge common packages."""
    items = list(items)
    items.sort()  # Sort items lexicographically
    merged = []
    for item in items:
        if not merged or not item.startswith(merged[-1] + '.'):
            merged.append(item)
    return merged


def extract_packages(file_data):
    """Extract package names from file data."""
    packages = set()
    try:
        for item in file_data:
            # tuple has file path and file content
            # we are interested in file content's first line
            pkg = item[1].split('\n')[0]
            match = PKG_REGEX.search(pkg)
            if match and match.group(1) != '_COROUTINE':
                packages.add(match.group(1))
        packages = merge_common_packages(packages)
    except Exception:
        logger.exception('Extracting packages from file data')
    return sorted(packages)


def android_sbom(app_dir):
    """Extract SBOM from files."""
    versioned, _ = extract_android_components(app_dir)
    return versioned


def sbom(app_dir, file_data):
    """Extract SBOM from version files, build manifests, and OSV database."""
    versioned, components = extract_android_components(app_dir)
    return {
        'sbom_versioned': versioned,
        'sbom_packages': extract_packages(file_data),
        'sbom_vulnerabilities': check_osv_vulnerabilities(components),
    }
