# -*- coding: utf_8 -*-
"""Module holding the functions for the db."""

from MobSF.utils import (
    PrintException,
    python_list,
    python_dict
)

from StaticAnalyzer.models import StaticAnalyzerAndroid


def get_context_from_db_entry(db_entry):
    """Return the context dict for an apk-DB entry."""
    try:
        print "\n[INFO] Analysis is already Done. Fetching data from the DB..."

        context = {
            'title': db_entry[0].TITLE,
            'name': db_entry[0].APP_NAME,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'packagename': db_entry[0].PACKAGENAME,
            'mainactivity': db_entry[0].MAINACTIVITY,
            'targetsdk': db_entry[0].TARGET_SDK,
            'maxsdk': db_entry[0].MAX_SDK,
            'minsdk': db_entry[0].MIN_SDK,
            'androvername': db_entry[0].ANDROVERNAME,
            'androver': db_entry[0].ANDROVER,
            'manifest': python_list(db_entry[0].MANIFEST_ANAL),
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'binary_analysis': python_list(db_entry[0].BIN_ANALYSIS),
            'androperms': db_entry[0].ANDROPERMS,
            'files': python_list(db_entry[0].FILES),
            'certz': db_entry[0].CERTZ,
            'activities': python_list(db_entry[0].ACTIVITIES),
            'receivers': python_list(db_entry[0].RECEIVERS),
            'providers': python_list(db_entry[0].PROVIDERS),
            'services': python_list(db_entry[0].SERVICES),
            'libraries': python_list(db_entry[0].LIBRARIES),
            'browsable_activities': python_dict(db_entry[0].BROWSABLE),
            'act_count': db_entry[0].CNT_ACT,
            'prov_count': db_entry[0].CNT_PRO,
            'serv_count': db_entry[0].CNT_SER,
            'bro_count': db_entry[0].CNT_BRO,
            'certinfo': db_entry[0].CERT_INFO,
            'issued': db_entry[0].ISSUED,
            'native': db_entry[0].NATIVE,
            'dynamic': db_entry[0].DYNAMIC,
            'reflection': db_entry[0].REFLECT,
            'crypto': db_entry[0].CRYPTO,
            'obfus': db_entry[0].OBFUS,
            'api': db_entry[0].API,
            'dang': db_entry[0].DANG,
            'urls': db_entry[0].URLS,
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': db_entry[0].EMAILS,
            'strings': python_list(db_entry[0].STRINGS),
            'apkid': '',
            'zipped': db_entry[0].ZIPPED,
            'mani': db_entry[0].MANI,
            'e_act': db_entry[0].E_ACT,
            'e_ser': db_entry[0].E_SER,
            'e_bro': db_entry[0].E_BRO,
            'e_cnt': db_entry[0].E_CNT,
        }
        return context
    except:
        PrintException("[ERROR] Fetching from DB")


def get_context_from_an(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, elf_an_buff, androperms):
    """Get the context for the webpage."""
    try:
        context = {
            'title': 'Static Analysis',
            'name': app_dic['app_name'],
            'size': app_dic['size'],
            'md5': app_dic['md5'],
            'sha1': app_dic['sha1'],
            'sha256': app_dic['sha256'],
            'packagename': man_data_dic['packagename'],
            'mainactivity': man_data_dic['mainactivity'],
            'targetsdk': man_data_dic['target_sdk'],
            'maxsdk': man_data_dic['max_sdk'],
            'minsdk': man_data_dic['min_sdk'],
            'androvername': man_data_dic['androvername'],
            'androver': man_data_dic['androver'],
            'manifest': man_an_dic['manifest_anal'],
            'permissions': man_an_dic['permissons'],
            'binary_analysis': elf_an_buff,
            'androperms': androperms,
            'files': app_dic['files'],
            'certz': app_dic['certz'],
            'activities': man_data_dic['activities'],
            'receivers': man_data_dic['receivers'],
            'providers': man_data_dic['providers'],
            'services': man_data_dic['services'],
            'libraries': man_data_dic['libraries'],
            'browsable_activities': man_an_dic['browsable_activities'],
            'act_count': man_an_dic['cnt_act'],
            'prov_count': man_an_dic['cnt_pro'],
            'serv_count': man_an_dic['cnt_ser'],
            'bro_count': man_an_dic['cnt_bro'],
            'certinfo': cert_dic['cert_info'],
            'issued': cert_dic['issued'],
            'native': code_an_dic['native'],
            'dynamic': code_an_dic['dynamic'],
            'reflection': code_an_dic['reflect'],
            'crypto': code_an_dic['crypto'],
            'obfus': code_an_dic['obfus'],
            'api': code_an_dic['api'],
            'dang': code_an_dic['dang'],
            'urls': code_an_dic['urls'],
            'domains': code_an_dic['domains'],
            'emails': code_an_dic['emails'],
            'strings': app_dic['strings'],
            'apkid': '',
            'zipped': app_dic['zipped'],
            'mani': app_dic['mani'],
            'e_act': man_an_dic['exported_cnt']["act"],
            'e_ser': man_an_dic['exported_cnt']["ser"],
            'e_bro': man_an_dic['exported_cnt']["bro"],
            'e_cnt': man_an_dic['exported_cnt']["cnt"],
        }
        return context
    except:
        PrintException("[ERROR] Rendering to Template")


def update_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, elf_an_buff, andro_perms):
    """Update an DB entry."""
    try:
        # pylint: disable=E1101
        StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5']).update(
            TITLE='Static Analysis',
            APP_NAME=app_dic['app_name'],
            SIZE=app_dic['size'],
            MD5=app_dic['md5'],
            SHA1=app_dic['sha1'],
            SHA256=app_dic['sha256'],
            PACKAGENAME=man_data_dic['packagename'],
            MAINACTIVITY=man_data_dic['mainactivity'],
            TARGET_SDK=man_data_dic['target_sdk'],
            MAX_SDK=man_data_dic['max_sdk'],
            MIN_SDK=man_data_dic['min_sdk'],
            ANDROVERNAME=man_data_dic['androvername'],
            ANDROVER=man_data_dic['androver'],
            MANIFEST_ANAL=man_an_dic['manifest_anal'],
            PERMISSIONS=man_an_dic['permissons'],
            BIN_ANALYSIS=elf_an_buff,
            ANDROPERMS=andro_perms,
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ACTIVITIES=man_data_dic['activities'],
            RECEIVERS=man_data_dic['receivers'],
            PROVIDERS=man_data_dic['providers'],
            SERVICES=man_data_dic['services'],
            LIBRARIES=man_data_dic['libraries'],
            BROWSABLE=man_an_dic['browsable_activities'],
            CNT_ACT=man_an_dic['cnt_act'],
            CNT_PRO=man_an_dic['cnt_pro'],
            CNT_SER=man_an_dic['cnt_ser'],
            CNT_BRO=man_an_dic['cnt_bro'],
            CERT_INFO=cert_dic['cert_info'],
            ISSUED=cert_dic['issued'],
            NATIVE=code_an_dic['native'],
            DYNAMIC=code_an_dic['dynamic'],
            REFLECT=code_an_dic['reflect'],
            CRYPTO=code_an_dic['crypto'],
            OBFUS=code_an_dic['obfus'],
            API=code_an_dic['api'],
            DANG=code_an_dic['dang'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS=app_dic['strings'],
            APKID='',
            ZIPPED=app_dic['zipped'],
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"]
        )
    except:
        PrintException("[ERROR] Updating DB")


def create_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, elf_an_buff, andro_perms):
    """Create a new DB-Entry."""
    try:
        static_db = StaticAnalyzerAndroid(
            TITLE='Static Analysis',
            APP_NAME=app_dic['app_name'],
            SIZE=app_dic['size'],
            MD5=app_dic['md5'],
            SHA1=app_dic['sha1'],
            SHA256=app_dic['sha256'],
            PACKAGENAME=man_data_dic['packagename'],
            MAINACTIVITY=man_data_dic['mainactivity'],
            TARGET_SDK=man_data_dic['target_sdk'],
            MAX_SDK=man_data_dic['max_sdk'],
            MIN_SDK=man_data_dic['min_sdk'],
            ANDROVERNAME=man_data_dic['androvername'],
            ANDROVER=man_data_dic['androver'],
            MANIFEST_ANAL=man_an_dic['manifest_anal'],
            PERMISSIONS=man_an_dic['permissons'],
            BIN_ANALYSIS=elf_an_buff,
            ANDROPERMS=andro_perms,
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ACTIVITIES=man_data_dic['activities'],
            RECEIVERS=man_data_dic['receivers'],
            PROVIDERS=man_data_dic['providers'],
            SERVICES=man_data_dic['services'],
            LIBRARIES=man_data_dic['libraries'],
            BROWSABLE=man_an_dic['browsable_activities'],
            CNT_ACT=man_an_dic['cnt_act'],
            CNT_PRO=man_an_dic['cnt_pro'],
            CNT_SER=man_an_dic['cnt_ser'],
            CNT_BRO=man_an_dic['cnt_bro'],
            CERT_INFO=cert_dic['cert_info'],
            ISSUED=cert_dic['issued'],
            NATIVE=code_an_dic['native'],
            DYNAMIC=code_an_dic['dynamic'],
            REFLECT=code_an_dic['reflect'],
            CRYPTO=code_an_dic['crypto'],
            OBFUS=code_an_dic['obfus'],
            API=code_an_dic['api'],
            DANG=code_an_dic['dang'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS=app_dic['strings'],
            APKID='',
            ZIPPED=app_dic['zipped'],
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"]
        )
        static_db.save()
    except:
        PrintException("[ERROR] Saving to DB")


def get_context_from_db_entry_zip(db_entry):
    """Get the context from an DB entry, zip type."""
    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
    try:
        context = {
            'title': db_entry[0].TITLE,
            'name': db_entry[0].APP_NAME,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'packagename': db_entry[0].PACKAGENAME,
            'mainactivity': db_entry[0].MAINACTIVITY,
            'targetsdk': db_entry[0].TARGET_SDK,
            'maxsdk': db_entry[0].MAX_SDK,
            'minsdk': db_entry[0].MIN_SDK,
            'androvername': db_entry[0].ANDROVERNAME,
            'androver': db_entry[0].ANDROVER,
            'manifest': python_list(db_entry[0].MANIFEST_ANAL),
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'files': python_list(db_entry[0].FILES),
            'certz': db_entry[0].CERTZ,
            'activities': python_list(db_entry[0].ACTIVITIES),
            'receivers': python_list(db_entry[0].RECEIVERS),
            'providers': python_list(db_entry[0].PROVIDERS),
            'services': python_list(db_entry[0].SERVICES),
            'libraries': python_list(db_entry[0].LIBRARIES),
            'browsable_activities': python_dict(db_entry[0].BROWSABLE),
            'act_count': db_entry[0].CNT_ACT,
            'prov_count': db_entry[0].CNT_PRO,
            'serv_count': db_entry[0].CNT_SER,
            'bro_count': db_entry[0].CNT_BRO,
            'native': db_entry[0].NATIVE,
            'dynamic': db_entry[0].DYNAMIC,
            'reflection': db_entry[0].REFLECT,
            'crypto': db_entry[0].CRYPTO,
            'obfus': db_entry[0].OBFUS,
            'api': db_entry[0].API,
            'dang': db_entry[0].DANG,
            'urls': db_entry[0].URLS,
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': db_entry[0].EMAILS,
            'mani': db_entry[0].MANI,
            'e_act': db_entry[0].E_ACT,
            'e_ser': db_entry[0].E_SER,
            'e_bro': db_entry[0].E_BRO,
            'e_cnt': db_entry[0].E_CNT,
        }
        return context
    except:
        PrintException("[ERROR] Fetching from DB")


def get_context_from_an_zip(app_dic, man_data_dic, man_an_dic, code_an_dic):
    """Get the context for the website, zip type."""
    try:
        context = {
            'title': 'Static Analysis',
            'name': app_dic['app_name'],
            'size': app_dic['size'],
            'md5': app_dic['md5'],
            'sha1': app_dic['sha1'],
            'sha256': app_dic['sha256'],
            'packagename': man_data_dic['packagename'],
            'mainactivity': man_data_dic['mainactivity'],
            'targetsdk': man_data_dic['target_sdk'],
            'maxsdk': man_data_dic['max_sdk'],
            'minsdk': man_data_dic['min_sdk'],
            'androvername': man_data_dic['androvername'],
            'androver': man_data_dic['androver'],
            'manifest': man_an_dic['manifest_anal'],
            'permissions': man_an_dic['permissons'],
            'files': app_dic['files'],
            'certz': app_dic['certz'],
            'activities': man_data_dic['activities'],
            'receivers': man_data_dic['receivers'],
            'providers': man_data_dic['providers'],
            'services': man_data_dic['services'],
            'libraries': man_data_dic['libraries'],
            'browsable_activities': man_an_dic['browsable_activities'],
            'act_count': man_an_dic['cnt_act'],
            'prov_count': man_an_dic['cnt_pro'],
            'serv_count': man_an_dic['cnt_ser'],
            'bro_count': man_an_dic['cnt_bro'],
            'native': code_an_dic['native'],
            'dynamic': code_an_dic['dynamic'],
            'reflection': code_an_dic['reflect'],
            'crypto': code_an_dic['crypto'],
            'obfus': code_an_dic['obfus'],
            'api': code_an_dic['api'],
            'dang': code_an_dic['dang'],
            'urls': code_an_dic['urls'],
            'domains': code_an_dic['domains'],
            'emails': code_an_dic['emails'],
            'mani': app_dic['mani'],
            'e_act': man_an_dic['exported_cnt']["act"],
            'e_ser': man_an_dic['exported_cnt']["ser"],
            'e_bro': man_an_dic['exported_cnt']["bro"],
            'e_cnt': man_an_dic['exported_cnt']["cnt"],
        }
        return context
    except:
        PrintException("[ERROR] Rendering to Template")


def update_db_entry_zip(app_dic, man_data_dic, man_an_dic, code_an_dic):
    """Update an DB-Entry, zip type."""
    try:
        # pylint: disable=E1101
        StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5']).update(
            TITLE='Static Analysis',
            APP_NAME=app_dic['app_name'],
            SIZE=app_dic['size'],
            MD5=app_dic['md5'],
            SHA1=app_dic['sha1'],
            SHA256=app_dic['sha256'],
            PACKAGENAME=man_data_dic['packagename'],
            MAINACTIVITY=man_data_dic['mainactivity'],
            TARGET_SDK=man_data_dic['target_sdk'],
            MAX_SDK=man_data_dic['max_sdk'],
            MIN_SDK=man_data_dic['min_sdk'],
            ANDROVERNAME=man_data_dic['androvername'],
            ANDROVER=man_data_dic['androver'],
            MANIFEST_ANAL=man_an_dic['manifest_anal'],
            PERMISSIONS=man_an_dic['permissons'],
            BIN_ANALYSIS=[],
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ACTIVITIES=man_data_dic['activities'],
            RECEIVERS=man_data_dic['receivers'],
            PROVIDERS=man_data_dic['providers'],
            SERVICES=man_data_dic['services'],
            LIBRARIES=man_data_dic['libraries'],
            BROWSABLE=man_an_dic['browsable_activities'],
            CNT_ACT=man_an_dic['cnt_act'],
            CNT_PRO=man_an_dic['cnt_pro'],
            CNT_SER=man_an_dic['cnt_ser'],
            CNT_BRO=man_an_dic['cnt_bro'],
            CERT_INFO="",
            ISSUED="",
            NATIVE=code_an_dic['native'],
            DYNAMIC=code_an_dic['dynamic'],
            REFLECT=code_an_dic['reflect'],
            CRYPTO=code_an_dic['crypto'],
            OBFUS=code_an_dic['obfus'],
            API=code_an_dic['api'],
            DANG=code_an_dic['dang'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS="",
            ZIPPED="",
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"]
        )
    except:
        PrintException("[ERROR] Updating to DB")


def create_db_entry_zip(app_dic, man_data_dic, man_an_dic, code_an_dic):
    """Create a new DB-Entry, zip type."""
    try:
        static_db = StaticAnalyzerAndroid(
            TITLE='Static Analysis',
            APP_NAME=app_dic['app_name'],
            SIZE=app_dic['size'],
            MD5=app_dic['md5'],
            SHA1=app_dic['sha1'],
            SHA256=app_dic['sha256'],
            PACKAGENAME=man_data_dic['packagename'],
            MAINACTIVITY=man_data_dic['mainactivity'],
            TARGET_SDK=man_data_dic['target_sdk'],
            MAX_SDK=man_data_dic['max_sdk'],
            MIN_SDK=man_data_dic['min_sdk'],
            ANDROVERNAME=man_data_dic['androvername'],
            ANDROVER=man_data_dic['androver'],
            MANIFEST_ANAL=man_an_dic['manifest_anal'],
            PERMISSIONS=man_an_dic['permissons'],
            BIN_ANALYSIS=[],
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ACTIVITIES=man_data_dic['activities'],
            RECEIVERS=man_data_dic['receivers'],
            PROVIDERS=man_data_dic['providers'],
            SERVICES=man_data_dic['services'],
            LIBRARIES=man_data_dic['libraries'],
            BROWSABLE=man_an_dic['browsable_activities'],
            CNT_ACT=man_an_dic['cnt_act'],
            CNT_PRO=man_an_dic['cnt_pro'],
            CNT_SER=man_an_dic['cnt_ser'],
            CNT_BRO=man_an_dic['cnt_bro'],
            CERT_INFO="",
            ISSUED="",
            NATIVE=code_an_dic['native'],
            DYNAMIC=code_an_dic['dynamic'],
            REFLECT=code_an_dic['reflect'],
            CRYPTO=code_an_dic['crypto'],
            OBFUS=code_an_dic['obfus'],
            API=code_an_dic['api'],
            DANG=code_an_dic['dang'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS="",
            ZIPPED="",
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"]
        )
        static_db.save()
    except:
        PrintException("[ERROR] Saving to DB")
