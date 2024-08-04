"""Module holding the functions for the db."""
import logging

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    get_scan_logs,
    python_dict,
    python_list,
)
from mobsf.MobSF.views.home import update_scan_timestamp
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.common.suppression import (
    process_suppression,
)

logger = logging.getLogger(__name__)


def get_context_from_db_entry(db_entry):
    """Return the context for IPA/ZIP from DB."""
    try:
        msg = 'Analysis is already Done. Fetching data from the DB...'
        logger.info(msg)
        bundle_id = db_entry[0].BUNDLE_ID
        code = process_suppression(
            python_dict(db_entry[0].CODE_ANALYSIS),
            bundle_id)
        binary = process_suppression(
            python_dict(db_entry[0].BINARY_ANALYSIS),
            bundle_id)
        context = {
            'version': settings.MOBSF_VER,
            'title': 'Static Analysis',
            'file_name': db_entry[0].FILE_NAME,
            'app_name': db_entry[0].APP_NAME,
            'app_type': db_entry[0].APP_TYPE,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'build': db_entry[0].BUILD,
            'app_version': db_entry[0].APP_VERSION,
            'sdk_name': db_entry[0].SDK_NAME,
            'platform': db_entry[0].PLATFORM,
            'min_os_version': db_entry[0].MIN_OS_VERSION,
            'bundle_id': bundle_id,
            'bundle_url_types': python_list(db_entry[0].BUNDLE_URL_TYPES),
            'bundle_supported_platforms':
                python_list(db_entry[0].BUNDLE_SUPPORTED_PLATFORMS),
            'icon_path': db_entry[0].ICON_PATH,
            'info_plist': db_entry[0].INFO_PLIST,
            'binary_info': python_dict(db_entry[0].BINARY_INFO),
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'ats_analysis': python_dict(db_entry[0].ATS_ANALYSIS),
            'binary_analysis': binary,
            'macho_analysis': python_dict(db_entry[0].MACHO_ANALYSIS),
            'dylib_analysis': python_list(db_entry[0].DYLIB_ANALYSIS),
            'framework_analysis': python_list(db_entry[0].FRAMEWORK_ANALYSIS),
            'ios_api': python_dict(db_entry[0].IOS_API),
            'code_analysis': code,
            'file_analysis': python_list(db_entry[0].FILE_ANALYSIS),
            'libraries': python_list(db_entry[0].LIBRARIES),
            'files': python_list(db_entry[0].FILES),
            'urls': python_list(db_entry[0].URLS),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EMAILS),
            'strings': python_list(db_entry[0].STRINGS),
            'firebase_urls': python_list(db_entry[0].FIREBASE_URLS),
            'appstore_details': python_dict(db_entry[0].APPSTORE_DETAILS),
            'secrets': python_list(db_entry[0].SECRETS),
            'trackers': python_dict(db_entry[0].TRACKERS),
            'logs': get_scan_logs(db_entry[0].MD5),
        }
        return context
    except Exception:
        msg = 'Fetching data from the DB failed.'
        logger.exception(msg)


def get_context_from_analysis(app_dict,
                              info_dict,
                              code_dict,
                              bin_dict,
                              all_files):
    """Get the context for IPA/ZIP from analysis results."""
    try:
        bundle_id = info_dict['id']
        code = process_suppression(
            code_dict['code_anal'],
            bundle_id)
        binary = process_suppression(
            bin_dict['bin_code_analysis'],
            bundle_id)
        context = {
            'version': settings.MOBSF_VER,
            'title': 'Static Analysis',
            'file_name': app_dict['file_name'],
            'app_name': info_dict['bin_name'],
            'app_type': bin_dict['bin_type'],
            'size': app_dict['size'],
            'md5': app_dict['md5_hash'],
            'sha1': app_dict['sha1'],
            'sha256': app_dict['sha256'],
            'build': info_dict['build'],
            'app_version': info_dict['bundle_version_name'],
            'sdk_name': info_dict['sdk'],
            'platform': info_dict['pltfm'],
            'min_os_version': info_dict['min'],
            'bundle_id': bundle_id,
            'bundle_url_types': info_dict['bundle_url_types'],
            'bundle_supported_platforms':
                info_dict['bundle_supported_platforms'],
            'icon_path': app_dict['icon_path'],
            'info_plist': info_dict['plist_xml'],
            'binary_info': bin_dict['bin_info'],
            'permissions': info_dict['permissions'],
            'ats_analysis': info_dict['inseccon'],
            'binary_analysis': binary,
            'macho_analysis': bin_dict['checksec'],
            'dylib_analysis': bin_dict['dylib_analysis'],
            'framework_analysis': bin_dict['framework_analysis'],
            'ios_api': code_dict['api'],
            'code_analysis': code,
            'file_analysis': all_files['special_files'],
            'libraries': bin_dict['libraries'],
            'files': all_files['files_short'],
            'urls': code_dict['urlnfile'],
            'domains': code_dict['domains'],
            'emails': code_dict['emailnfile'],
            'strings': bin_dict['strings'],
            'firebase_urls': code_dict['firebase'],
            'appstore_details': app_dict['appstore'],
            'secrets': app_dict['secrets'],
            'trackers': code_dict['trackers'],
            'logs': get_scan_logs(app_dict['md5_hash']),
        }
        return context
    except Exception as exp:
        msg = 'Rendering to Template'
        logger.exception(msg)
        append_scan_status(app_dict['md5_hash'], msg, repr(exp))


def save_or_update(update_type,
                   app_dict,
                   info_dict,
                   code_dict,
                   bin_dict,
                   all_files):
    """Save/Update an IPA/ZIP DB entry."""
    try:
        values = {
            'FILE_NAME': app_dict['file_name'],
            'APP_NAME': info_dict['bin_name'],
            'APP_TYPE': bin_dict['bin_type'],
            'SIZE': app_dict['size'],
            'MD5': app_dict['md5_hash'],
            'SHA1': app_dict['sha1'],
            'SHA256': app_dict['sha256'],
            'BUILD': info_dict['build'],
            'APP_VERSION': info_dict['bundle_version_name'],
            'SDK_NAME': info_dict['sdk'],
            'PLATFORM': info_dict['pltfm'],
            'MIN_OS_VERSION': info_dict['min'],
            'BUNDLE_ID': info_dict['id'],
            'BUNDLE_URL_TYPES': info_dict['bundle_url_types'],
            'BUNDLE_SUPPORTED_PLATFORMS':
                info_dict['bundle_supported_platforms'],
            'ICON_PATH': app_dict['icon_path'],
            'INFO_PLIST': info_dict['plist_xml'],
            'BINARY_INFO': bin_dict['bin_info'],
            'PERMISSIONS': info_dict['permissions'],
            'ATS_ANALYSIS': info_dict['inseccon'],
            'BINARY_ANALYSIS': bin_dict['bin_code_analysis'],
            'MACHO_ANALYSIS': bin_dict['checksec'],
            'DYLIB_ANALYSIS': bin_dict['dylib_analysis'],
            'FRAMEWORK_ANALYSIS': bin_dict['framework_analysis'],
            'IOS_API': code_dict['api'],
            'CODE_ANALYSIS': code_dict['code_anal'],
            'FILE_ANALYSIS': all_files['special_files'],
            'LIBRARIES': bin_dict['libraries'],
            'FILES': all_files['files_short'],
            'URLS': code_dict['urlnfile'],
            'DOMAINS': code_dict['domains'],
            'EMAILS': code_dict['emailnfile'],
            'STRINGS': bin_dict['strings'],
            'FIREBASE_URLS': code_dict['firebase'],
            'APPSTORE_DETAILS': app_dict['appstore'],
            'SECRETS': app_dict['secrets'],
            'TRACKERS': code_dict['trackers'],
        }
        if update_type == 'save':
            db_entry = StaticAnalyzerIOS.objects.filter(
                MD5=app_dict['md5_hash'])
            if not db_entry.exists():
                StaticAnalyzerIOS.objects.create(**values)
        else:
            StaticAnalyzerIOS.objects.filter(
                MD5=app_dict['md5_hash']).update(**values)
    except Exception as exp:
        msg = 'Failed to Save/Update Database'
        logger.exception(msg)
        append_scan_status(app_dict['md5_hash'], msg, repr(exp))
    try:
        values = {
            'APP_NAME': info_dict['bin_name'],
            'PACKAGE_NAME': info_dict['id'],
            'VERSION_NAME': info_dict['bundle_version_name'],
        }
        RecentScansDB.objects.filter(
            MD5=app_dict['md5_hash']).update(**values)
    except Exception as exp:
        msg = 'Updating RecentScansDB table failed'
        logger.exception(msg)
        append_scan_status(app_dict['md5_hash'], msg, repr(exp))


def save_get_ctx(app_dict, pdict, code_dict, bin_dict, all_files, rescan):
    # Saving to DB
    logger.info('Connecting to DB')
    if rescan:
        msg = 'Updating Database...'
        logger.info(msg)
        append_scan_status(app_dict['md5_hash'], msg)
        action = 'update'
        update_scan_timestamp(app_dict['md5_hash'])
    else:
        msg = 'Saving to Database'
        logger.info(msg)
        append_scan_status(app_dict['md5_hash'], msg)
        action = 'save'
    save_or_update(
        action,
        app_dict,
        pdict,
        code_dict,
        bin_dict,
        all_files)
    return get_context_from_analysis(
        app_dict,
        pdict,
        code_dict,
        bin_dict,
        all_files)
