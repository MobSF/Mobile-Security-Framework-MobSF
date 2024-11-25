# -*- coding: utf_8 -*-
"""Extract packages from APK."""
import logging

from mobsf.MobSF.utils import (
    PKG_REGEX,
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


def get_group_name(file_name, group):
    """Get group and name from file name."""
    parts = file_name.split('_')

    if parts and len(parts) == 2:
        group, name = parts[0], parts[1]
    else:
        name = file_name.replace('_', '-')
        if name.startswith('kotlinx-'):
            group = 'org.jetbrains.kotlinx'

    return group, name


def android_sbom(app_dir):
    """Extract SBOM from files."""
    sbom = set()
    for vfile in app_dir.rglob('*.version'):
        try:
            dependency = vfile.stem
            group, name = '', ''
            version = vfile.read_text().strip() or ''
            version = 'dynamic' if version.startswith('task') else version

            if '_' in dependency:
                group, name = get_group_name(dependency, group)
            sbom.add(f'{group}:{name}@{version}')
        except Exception:
            pass
    return sorted(sbom)


def sbom(app_dir, file_data):
    """Extract SBOM from version files and decompiled source code."""
    return {
        'sbom_versioned': android_sbom(app_dir),
        'sbom_packages': extract_packages(file_data),
    }
