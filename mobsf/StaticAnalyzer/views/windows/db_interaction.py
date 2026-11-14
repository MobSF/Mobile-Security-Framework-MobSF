"""Module holding the functions for the db."""
import logging

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    get_scan_logs,
    python_dict,
    python_list,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerWindows,
)

logger = logging.getLogger(__name__)


def _display_name(manifest):
    """Prefer the display name unless it is an unresolved resource key."""
    name = manifest.get('app_name', '')
    if not name or name.startswith('ms-resource:'):
        return manifest.get('package_name', '')
    return name


def get_context_from_db_entry(db_entry):
    """Return the context for APPX/MSIX from DB."""
    logger.info('Analysis is already Done. Fetching data from the DB...')
    entry = db_entry[0]
    return {
        'title': 'Static Analysis',
        'version': settings.MOBSF_VER,
        'file_name': entry.FILE_NAME,
        'app_name': entry.APP_NAME,
        'publisher_name': entry.PUBLISHER_NAME,
        'package_name': entry.PACKAGE_NAME,
        'publisher': entry.PUBLISHER,
        'package_type': entry.PACKAGE_TYPE,
        'size': entry.SIZE,
        'md5': entry.MD5,
        'sha1': entry.SHA1,
        'sha256': entry.SHA256,
        'app_version': entry.APP_VERSION,
        'architecture': entry.ARCHITECTURE,
        'min_os_version': entry.MIN_OS_VERSION,
        'compiler_version': entry.COMPILER_VERSION,
        'visual_studio_version': entry.VISUAL_STUDIO_VERSION,
        'visual_studio_edition': entry.VISUAL_STUDIO_EDITION,
        'target_os': entry.TARGET_OS,
        'appx_dll_version': entry.APPX_DLL_VERSION,
        'proj_guid': entry.PROJ_GUID,
        'opti_tool': entry.OPTI_TOOL,
        'target_run': entry.TARGET_RUN,
        'files': python_list(entry.FILES),
        'strings': python_list(entry.STRINGS),
        'pe_analysis': python_list(entry.PE_ANALYSIS),
        'manifest_analysis': python_list(entry.MANIFEST_ANALYSIS),
        'capabilities': python_list(entry.CAPABILITIES),
        'package_signature': python_dict(entry.PACKAGE_SIGNATURE),
        'urls': python_list(entry.URLS),
        'emails': python_list(entry.EMAILS),
        'domains': python_dict(entry.DOMAINS),
        'secrets': python_list(entry.SECRETS),
        'trackers': python_dict(entry.TRACKERS),
        'binary_analysis': python_list(entry.BINARY_ANALYSIS),
        'binary_warnings': python_list(entry.BINARY_WARNINGS),
        'logs': get_scan_logs(entry.MD5),
    }


def get_context_from_analysis(analysis):
    """Get the context for APPX/MSIX from analysis results."""
    manifest = analysis['manifest']
    signature = dict(analysis['signature'])
    signature.pop('findings', None)
    return {
        'title': 'Static Analysis',
        'version': settings.MOBSF_VER,
        'file_name': analysis['file_name'],
        'app_name': _display_name(manifest),
        'publisher_name': manifest['pub_name'],
        'package_name': manifest['package_name'],
        'publisher': manifest['publisher'],
        'package_type': analysis['package_type'],
        'size': analysis['size'],
        'md5': analysis['md5'],
        'sha1': analysis['sha1'],
        'sha256': analysis['sha256'],
        'app_version': manifest['version'],
        'architecture': manifest['arch'],
        'min_os_version': manifest['min_os_version'],
        'compiler_version': manifest['compiler_version'],
        'visual_studio_version': manifest['visual_studio_version'],
        'visual_studio_edition': manifest['visual_studio_edition'],
        'target_os': manifest['target_os'],
        'appx_dll_version': manifest['appx_dll_version'],
        'proj_guid': manifest['proj_guid'],
        'opti_tool': manifest['opti_tool'],
        'target_run': manifest['target_run'],
        'files': analysis['files'],
        'strings': analysis['strings'],
        'pe_analysis': analysis['pe_analysis'],
        'manifest_analysis': analysis['manifest_analysis'],
        'capabilities': manifest['capabilities'],
        'package_signature': signature,
        'urls': analysis['urls'],
        'emails': analysis['emails'],
        'domains': analysis['domains'],
        'secrets': analysis['secrets'],
        'trackers': analysis['trackers'],
        'binary_analysis': [],
        'binary_warnings': [],
        'logs': get_scan_logs(analysis['md5']),
    }


def save_or_update(analysis) -> None:
    """Save/Update an APPX/MSIX DB entry."""
    checksum = analysis['md5']
    context = get_context_from_analysis(analysis)
    try:
        values = {
            'FILE_NAME': context['file_name'],
            'APP_NAME': context['app_name'],
            'PUBLISHER_NAME': context['publisher_name'],
            'PACKAGE_NAME': context['package_name'],
            'PUBLISHER': context['publisher'],
            'PACKAGE_TYPE': context['package_type'],
            'SIZE': context['size'],
            'MD5': checksum,
            'SHA1': context['sha1'],
            'SHA256': context['sha256'],
            'APP_VERSION': context['app_version'],
            'ARCHITECTURE': context['architecture'],
            'MIN_OS_VERSION': context['min_os_version'],
            'COMPILER_VERSION': context['compiler_version'],
            'VISUAL_STUDIO_VERSION': context['visual_studio_version'],
            'VISUAL_STUDIO_EDITION': context['visual_studio_edition'],
            'TARGET_OS': context['target_os'],
            'APPX_DLL_VERSION': context['appx_dll_version'],
            'PROJ_GUID': context['proj_guid'],
            'OPTI_TOOL': context['opti_tool'],
            'TARGET_RUN': context['target_run'],
            'FILES': context['files'],
            'STRINGS': context['strings'],
            'PE_ANALYSIS': context['pe_analysis'],
            'MANIFEST_ANALYSIS': context['manifest_analysis'],
            'CAPABILITIES': context['capabilities'],
            'PACKAGE_SIGNATURE': context['package_signature'],
            'URLS': context['urls'],
            'EMAILS': context['emails'],
            'DOMAINS': context['domains'],
            'SECRETS': context['secrets'],
            'TRACKERS': context['trackers'],
            'BINARY_ANALYSIS': [],
            'BINARY_WARNINGS': [],
        }
        StaticAnalyzerWindows.objects.update_or_create(
            MD5=checksum, defaults=values)
    except Exception as exp:
        msg = 'Failed to Save/Update Database'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    try:
        RecentScansDB.objects.filter(MD5=checksum).update(
            APP_NAME=context['app_name'],
            PACKAGE_NAME=context['package_name'],
            VERSION_NAME=context['app_version'])
    except Exception as exp:
        msg = 'Updating RecentScansDB table failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
