"""Module holding the functions for the db."""
import logging

from MobSF.utils import python_dict, python_list

from StaticAnalyzer.models import StaticAnalyzerIOSZIP, StaticAnalyzerIPA

logger = logging.getLogger(__name__)
# IPA DB


def get_context_from_analysis_ipa(app_dict,
                                  info_dict,
                                  bin_dict,
                                  files,
                                  sfiles):
    """Get the context for IPA from analysis results."""
    try:
        context = {
            'title': 'Static Analysis',
            'file_name': app_dict['file_name'],
            'size': app_dict['size'],
            'md5': app_dict['md5_hash'],
            'sha1': app_dict['sha1'],
            'sha256': app_dict['sha256'],
            'plist': info_dict['plist_xml'],
            'bin_name': info_dict['bin_name'],
            'id': info_dict['id'],
            'build': info_dict['build'],
            'version': info_dict['bundle_version_name'],
            'sdk': info_dict['sdk'],
            'pltfm': info_dict['pltfm'],
            'min': info_dict['min'],
            'bin_anal': bin_dict['bin_res'],
            'libs': bin_dict['libs'],
            'files': files,
            'file_analysis': sfiles,
            'strings': bin_dict['strings'],
            'permissions': info_dict['permissions'],
            'insecure_connections': info_dict['inseccon'],
            'bundle_name': info_dict['bundle_name'],
            'bundle_url_types': info_dict['bundle_url_types'],
            'bundle_supported_platforms':
                info_dict['bundle_supported_platforms'],
            'bundle_localizations': info_dict['bundle_localizations'],
            'binary_info': bin_dict['macho'],
            'bin_type': bin_dict['bin_type'],
            'appstore_details': app_dict['appstore'],

        }
        return context
    except Exception:
        logger.exception('Rendering to Template')


def get_context_from_db_entry_ipa(db_entry):
    """Return the context for IPA from DB."""
    try:
        logger.info('Analysis is already Done. Fetching data from the DB...')
        context = {
            'title': db_entry[0].TITLE,
            'file_name': db_entry[0].FILE_NAME,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'plist': db_entry[0].INFOPLIST,
            'bin_name': db_entry[0].BINNAME,
            'id': db_entry[0].IDF,
            'build': db_entry[0].BUILD,
            'version': db_entry[0].VERSION,
            'sdk': db_entry[0].SDK,
            'pltfm': db_entry[0].PLTFM,
            'min': db_entry[0].MINX,
            'bin_anal': python_list(db_entry[0].BIN_ANAL),
            'libs': python_list(db_entry[0].LIBS),
            'files': python_list(db_entry[0].FILES),
            'file_analysis': python_list(db_entry[0].SFILESX),
            'strings': python_list(db_entry[0].STRINGS),
            'permissions': python_list(db_entry[0].PERMISSIONS),
            'insecure_connections': python_list(db_entry[0].INSECCON),
            'bundle_name': db_entry[0].BUNDLE_NAME,
            'bundle_url_types': python_list(db_entry[0].BUNDLE_URL_TYPES),
            'bundle_supported_platforms':
                python_list(db_entry[0].BUNDLE_SUPPORTED_PLATFORMS),
            'bundle_localizations':
                python_list(db_entry[0].BUNDLE_LOCALIZATIONS),
            'binary_info': python_dict(db_entry[0].MACHOINFO),
            'bin_type': db_entry[0].BINTYPE,
            'appstore_details': python_dict(db_entry[0].APPSTORE_DETAILS),

        }
        return context
    except Exception:
        logger.exception('Fetching from DB')


def update_db_entry_ipa(app_dict,
                        info_dict,
                        bin_dict,
                        files,
                        sfiles):
    """Update an IPA DB entry."""
    try:
        # pylint: disable=E1101
        StaticAnalyzerIPA.objects.filter(MD5=app_dict['md5_hash']).update(
            TITLE='Static Analysis',
            FILE_NAME=app_dict['file_name'],
            SIZE=app_dict['size'],
            MD5=app_dict['md5_hash'],
            SHA1=app_dict['sha1'],
            SHA256=app_dict['sha256'],
            INFOPLIST=info_dict['plist_xml'],
            BINNAME=info_dict['bin_name'],
            IDF=info_dict['id'],
            BUILD=info_dict['build'],
            VERSION=info_dict['bundle_version_name'],
            SDK=info_dict['sdk'],
            PLTFM=info_dict['pltfm'],
            MINX=info_dict['min'],
            BIN_ANAL=bin_dict['bin_res'],
            LIBS=bin_dict['libs'],
            FILES=files,
            SFILESX=sfiles,
            STRINGS=bin_dict['strings'],
            PERMISSIONS=info_dict['permissions'],
            INSECCON=info_dict['inseccon'],
            BUNDLE_NAME=info_dict['bundle_name'],
            BUNDLE_URL_TYPES=info_dict['bundle_url_types'],
            BUNDLE_SUPPORTED_PLATFORMS=info_dict['bundle_supported_platforms'],
            BUNDLE_LOCALIZATIONS=info_dict['bundle_localizations'],
            MACHOINFO=bin_dict['macho'],
            BINTYPE=bin_dict['bin_type'],
            APPSTORE_DETAILS=app_dict['appstore'],
        )

    except Exception:
        logger.exception('Updating DB')


def create_db_entry_ipa(app_dict,
                        info_dict,
                        bin_dict,
                        files,
                        sfiles):
    """Save an IOS IPA DB entry."""
    try:
        static_db = StaticAnalyzerIPA(
            TITLE='Static Analysis',
            FILE_NAME=app_dict['file_name'],
            SIZE=app_dict['size'],
            MD5=app_dict['md5_hash'],
            SHA1=app_dict['sha1'],
            SHA256=app_dict['sha256'],
            INFOPLIST=info_dict['plist_xml'],
            BINNAME=info_dict['bin_name'],
            IDF=info_dict['id'],
            BUILD=info_dict['build'],
            VERSION=info_dict['bundle_version_name'],
            SDK=info_dict['sdk'],
            PLTFM=info_dict['pltfm'],
            MINX=info_dict['min'],
            BIN_ANAL=bin_dict['bin_res'],
            LIBS=bin_dict['libs'],
            FILES=files,
            SFILESX=sfiles,
            STRINGS=bin_dict['strings'],
            PERMISSIONS=info_dict['permissions'],
            INSECCON=info_dict['inseccon'],
            BUNDLE_NAME=info_dict['bundle_name'],
            BUNDLE_URL_TYPES=info_dict['bundle_url_types'],
            BUNDLE_SUPPORTED_PLATFORMS=info_dict['bundle_supported_platforms'],
            BUNDLE_LOCALIZATIONS=info_dict['bundle_localizations'],
            MACHOINFO=bin_dict['macho'],
            BINTYPE=bin_dict['bin_type'],
            APPSTORE_DETAILS=app_dict['appstore'],
        )
        static_db.save()
    except Exception:
        logger.exception('Saving to DB')

# IOS ZIP DB ENTRY


def get_context_from_analysis_ios(app_dict,
                                  info_dict,
                                  code_dict,
                                  files,
                                  sfiles):
    """Get the context for IOS ZIP from analysis results."""
    try:
        context = {
            'title': 'Static Analysis',
            'file_name': app_dict['file_name'],
            'size': app_dict['size'],
            'md5': app_dict['md5_hash'],
            'sha1': app_dict['sha1'],
            'sha256': app_dict['sha256'],
            'plist': info_dict['plist_xml'],
            'bin_name': info_dict['bin_name'],
            'id': info_dict['id'],
            'build': info_dict['bundle_version_name'],
            'version': info_dict['bundle_version_name'],
            'sdk': info_dict['sdk'],
            'pltfm': info_dict['pltfm'],
            'min': info_dict['min'],
            'files': files,
            'file_analysis': sfiles,
            'api': code_dict['api'],
            'insecure': code_dict['code_anal'],
            'urls': code_dict['urlnfile'],
            'domains': code_dict['domains'],
            'emails': code_dict['emailnfile'],
            'permissions': info_dict['permissions'],
            'insecure_connections': info_dict['inseccon'],
            'bundle_name': info_dict['bundle_name'],
            'bundle_url_types': info_dict['bundle_url_types'],
            'bundle_supported_platforms':
                info_dict['bundle_supported_platforms'],
            'bundle_localizations': info_dict['bundle_localizations'],
            'appstore_details': app_dict['appstore'],
            'firebase': code_dict['firebase'],
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')


def get_context_from_db_entry_ios(db_entry):
    """Return the context for IOS ZIP from DB."""
    try:
        logger.info('Analysis is already Done. Fetching data from the DB...')
        context = {
            'title': db_entry[0].TITLE,
            'file_name': db_entry[0].FILE_NAME,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'plist': db_entry[0].INFOPLIST,
            'bin_name': db_entry[0].BINNAME,
            'id': db_entry[0].IDF,
            'build': db_entry[0].BUILD,
            'version': db_entry[0].VERSION,
            'sdk': db_entry[0].SDK,
            'pltfm': db_entry[0].PLTFM,
            'min': db_entry[0].MINX,
            'files': python_list(db_entry[0].FILES),
            'file_analysis': python_list(db_entry[0].SFILESX),
            'api': python_dict(db_entry[0].API),
            'insecure': python_dict(db_entry[0].CODEANAL),
            'urls': python_list(db_entry[0].URLnFile),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EmailnFile),
            'permissions': python_list(db_entry[0].PERMISSIONS),
            'insecure_connections': python_list(db_entry[0].INSECCON),
            'bundle_name': db_entry[0].BUNDLE_NAME,
            'bundle_url_types': python_list(db_entry[0].BUNDLE_URL_TYPES),
            'bundle_supported_platforms':
                python_list(db_entry[0].BUNDLE_SUPPORTED_PLATFORMS),
            'bundle_localizations':
                python_list(db_entry[0].BUNDLE_LOCALIZATIONS),
            'appstore_details': python_dict(db_entry[0].APPSTORE_DETAILS),
            'firebase': python_list(db_entry[0].FIREBASE),
        }
        return context
    except Exception:
        logger.exception('Fetching from DB')


def update_db_entry_ios(app_dict,
                        info_dict,
                        code_dict,
                        files,
                        sfiles):
    """Update an IOS ZIP DB entry."""
    try:
        # pylint: disable=E1101
        StaticAnalyzerIOSZIP.objects.filter(MD5=app_dict['md5_hash']).update(
            TITLE='Static Analysis',
            FILE_NAME=app_dict['file_name'],
            SIZE=app_dict['size'],
            MD5=app_dict['md5_hash'],
            SHA1=app_dict['sha1'],
            SHA256=app_dict['sha256'],
            INFOPLIST=info_dict['plist_xml'],
            BINNAME=info_dict['bin_name'],
            IDF=info_dict['id'],
            BUILD=info_dict['build'],
            VERSION=info_dict['bundle_version_name'],
            SDK=info_dict['sdk'],
            PLTFM=info_dict['pltfm'],
            MINX=info_dict['min'],
            FILES=files,
            SFILESX=sfiles,
            API=code_dict['api'],
            CODEANAL=code_dict['code_anal'],
            URLnFile=code_dict['urlnfile'],
            DOMAINS=code_dict['domains'],
            EmailnFile=code_dict['emailnfile'],
            PERMISSIONS=info_dict['permissions'],
            INSECCON=info_dict['inseccon'],
            BUNDLE_NAME=info_dict['bundle_name'],
            BUNDLE_URL_TYPES=info_dict['bundle_url_types'],
            BUNDLE_SUPPORTED_PLATFORMS=info_dict['bundle_supported_platforms'],
            BUNDLE_LOCALIZATIONS=info_dict['bundle_localizations'],
            APPSTORE_DETAILS=app_dict['appstore'],
            FIREBASE=code_dict['firebase'],
        )

    except Exception:
        logger.exception('Updating DB')


def create_db_entry_ios(app_dict, info_dict, code_dict, files, sfiles):
    """Save an IOS ZIP DB entry."""
    try:
        # pylint: disable=E1101
        static_db = StaticAnalyzerIOSZIP(
            TITLE='Static Analysis',
            FILE_NAME=app_dict['file_name'],
            SIZE=app_dict['size'],
            MD5=app_dict['md5_hash'],
            SHA1=app_dict['sha1'],
            SHA256=app_dict['sha256'],
            INFOPLIST=info_dict['plist_xml'],
            BINNAME=info_dict['bin_name'],
            IDF=info_dict['id'],
            BUILD=info_dict['build'],
            VERSION=info_dict['bundle_version_name'],
            SDK=info_dict['sdk'],
            PLTFM=info_dict['pltfm'],
            MINX=info_dict['min'],
            FILES=files,
            SFILESX=sfiles,
            API=code_dict['api'],
            CODEANAL=code_dict['code_anal'],
            URLnFile=code_dict['urlnfile'],
            DOMAINS=code_dict['domains'],
            EmailnFile=code_dict['emailnfile'],
            PERMISSIONS=info_dict['permissions'],
            INSECCON=info_dict['inseccon'],
            BUNDLE_NAME=info_dict['bundle_name'],
            BUNDLE_URL_TYPES=info_dict['bundle_url_types'],
            BUNDLE_SUPPORTED_PLATFORMS=info_dict['bundle_supported_platforms'],
            BUNDLE_LOCALIZATIONS=info_dict['bundle_localizations'],
            APPSTORE_DETAILS=app_dict['appstore'],
            FIREBASE=code_dict['firebase'],
        )
        static_db.save()
    except Exception:
        logger.exception('Saving DB')
