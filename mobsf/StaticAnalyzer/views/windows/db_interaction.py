"""Module holding the functions for the db."""
import logging

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    get_scan_logs,
    python_list,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerWindows
from mobsf.StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def get_context_from_db_entry(db_entry):
    """Return the context for APPX from DB."""
    try:
        logger.info('Analysis is already Done. Fetching data from the DB...')
        entry = db_entry[0]
        context = {
            'title': 'Static Analysis',
            'version': settings.MOBSF_VER,
            'file_name': entry.FILE_NAME,
            'app_name': entry.APP_NAME,
            'publisher_name': entry.PUBLISHER_NAME,
            'size': entry.SIZE,
            'md5': entry.MD5,
            'sha1': entry.SHA1,
            'sha256': entry.SHA256,
            'app_version': entry.APP_VERSION,
            'architecture': entry.ARCHITECTURE,
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
            'binary_analysis': python_list(entry.BINARY_ANALYSIS),
            'binary_warnings': python_list(entry.BINARY_WARNINGS),
            'logs': get_scan_logs(entry.MD5),
        }
        return context
    except Exception:
        logger.exception('Fetching from DB')


def get_context_from_analysis(app_dic,
                              xml_dic,
                              bin_an_dic):
    """Get the context for APPX from analysis results."""
    try:
        context = {
            'title': 'Static Analysis',
            'version': settings.MOBSF_VER,
            'file_name': app_dic['app_name'],
            'app_name': bin_an_dic['bin_name'],
            'publisher_name': xml_dic['pub_name'],
            'size': app_dic['size'],
            'md5': app_dic['md5'],
            'sha1': app_dic['sha1'],
            'sha256': app_dic['sha256'],
            'app_version': xml_dic['version'],
            'architecture': xml_dic['arch'],
            'compiler_version': xml_dic['compiler_version'],
            'visual_studio_version': xml_dic['visual_studio_version'],
            'visual_studio_edition': xml_dic['visual_studio_edition'],
            'target_os': xml_dic['target_os'],
            'appx_dll_version': xml_dic['appx_dll_version'],
            'proj_guid': xml_dic['proj_guid'],
            'opti_tool': xml_dic['opti_tool'],
            'target_run': xml_dic['target_run'],
            'files': app_dic['files'],
            'strings': bin_an_dic['strings'],
            'binary_analysis': bin_an_dic['results'],
            'binary_warnings': bin_an_dic['warnings'],
            'logs': get_scan_logs(app_dic['md5']),
        }
        return context
    except Exception as exp:
        msg = 'Rendering to Template'
        logger.exception(msg)
        append_scan_status(app_dic['md5'], msg, repr(exp))


def save_or_update(update_type,
                   app_dic,
                   xml_dic,
                   bin_an_dic) -> None:
    """Save/Update an APPX DB entry."""
    try:
        values = {
            'FILE_NAME': app_dic['app_name'],
            'APP_NAME': bin_an_dic['bin_name'],
            'PUBLISHER_NAME': xml_dic['pub_name'],
            'SIZE': app_dic['size'],
            'MD5': app_dic['md5'],
            'SHA1': app_dic['sha1'],
            'SHA256': app_dic['sha256'],
            'APP_VERSION': xml_dic['version'],
            'ARCHITECTURE': xml_dic['arch'],
            'COMPILER_VERSION': xml_dic['compiler_version'],
            'VISUAL_STUDIO_VERSION': xml_dic['visual_studio_version'],
            'VISUAL_STUDIO_EDITION': xml_dic['visual_studio_edition'],
            'TARGET_OS': xml_dic['target_os'],
            'APPX_DLL_VERSION': xml_dic['appx_dll_version'],
            'PROJ_GUID': xml_dic['proj_guid'],
            'OPTI_TOOL': xml_dic['opti_tool'],
            'TARGET_RUN': xml_dic['target_run'],
            'FILES': app_dic['files'],
            'STRINGS': bin_an_dic['strings'],
            'BINARY_ANALYSIS': bin_an_dic['results'],
            'BINARY_WARNINGS': bin_an_dic['warnings'],
        }
        if update_type == 'save':
            db_entry = StaticAnalyzerWindows.objects.filter(
                MD5=app_dic['md5'])
            if not db_entry.exists():
                StaticAnalyzerWindows.objects.create(**values)
        else:
            StaticAnalyzerWindows.objects.filter(
                MD5=app_dic['md5']).update(**values)
    except Exception as exp:
        msg = 'Failed to Save/Update Database'
        logger.exception(msg)
        append_scan_status(app_dic['md5'], msg, repr(exp))
    try:
        values = {
            'APP_NAME': bin_an_dic['bin_name'],
            'PACKAGE_NAME': xml_dic['pub_name'],
            'VERSION_NAME': xml_dic['version'],
        }
        RecentScansDB.objects.filter(
            MD5=app_dic['md5']).update(**values)
    except Exception as exp:
        msg = 'Updating RecentScansDB table failed'
        logger.exception(msg)
        append_scan_status(app_dic['md5'], msg, repr(exp))
