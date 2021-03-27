"""Module holding the functions for the db."""
import logging

from django.conf import settings

from mobsf.MobSF.utils import python_list
from mobsf.StaticAnalyzer.models import StaticAnalyzerWindows
from mobsf.StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def get_context_from_db_entry(db_entry):
    """Return the context for APPX from DB."""
    try:
        logger.info('Analysis is already Done. Fetching data from the DB...')
        context = {
            'title': 'Static Analysis',
            'version': settings.MOBSF_VER,
            'file_name': db_entry[0].FILE_NAME,
            'app_name': db_entry[0].APP_NAME,
            'publisher_name': db_entry[0].PUBLISHER_NAME,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'app_version': db_entry[0].APP_VERSION,
            'architecture': db_entry[0].ARCHITECTURE,
            'compiler_version': db_entry[0].COMPILER_VERSION,
            'visual_studio_version': db_entry[0].VISUAL_STUDIO_VERSION,
            'visual_studio_edition': db_entry[0].VISUAL_STUDIO_EDITION,
            'target_os': db_entry[0].TARGET_OS,
            'appx_dll_version': db_entry[0].APPX_DLL_VERSION,
            'proj_guid': db_entry[0].PROJ_GUID,
            'opti_tool': db_entry[0].OPTI_TOOL,
            'target_run': db_entry[0].TARGET_RUN,
            'files': python_list(db_entry[0].FILES),
            'strings': python_list(db_entry[0].STRINGS),
            'binary_analysis': python_list(db_entry[0].BINARY_ANALYSIS),
            'binary_warnings': python_list(db_entry[0].BINARY_WARNINGS),
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
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')


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
    except Exception:
        logger.exception('Updating DB')
    try:
        values = {
            'APP_NAME': bin_an_dic['bin_name'],
            'PACKAGE_NAME': xml_dic['pub_name'],
            'VERSION_NAME': xml_dic['version'],
        }
        RecentScansDB.objects.filter(
            MD5=app_dic['md5']).update(**values)
    except Exception:
        logger.exception('Updating RecentScansDB')
