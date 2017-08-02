# -*- coding: utf_8 -*-
"""Module holding the functions for the db."""

from MobSF.utils import (
    PrintException,
    python_list,
    python_dict
)

from StaticAnalyzer.models import StaticAnalyzerAndroid


def get_context_from_db_entry(db_entry):
    """Return the context for APK/ZIP from DB"""
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
            'files': python_list(db_entry[0].FILES),
            'certz': db_entry[0].CERTZ,
            'icon_hidden': db_entry[0].ICON_HIDDEN,
            'icon_found': db_entry[0].ICON_FOUND,
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
            'api': python_dict(db_entry[0].API),
            'findings': python_dict(db_entry[0].DANG),
            'urls': python_list(db_entry[0].URLS),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EMAILS),
            'strings': python_list(db_entry[0].STRINGS),
            'zipped': db_entry[0].ZIPPED,
            'mani': db_entry[0].MANI,
            'e_act': db_entry[0].E_ACT,
            'e_ser': db_entry[0].E_SER,
            'e_bro': db_entry[0].E_BRO,
            'e_cnt': db_entry[0].E_CNT,
            'apkid': python_dict(db_entry[0].APK_ID),
        }
        return context
    except:
        PrintException("[ERROR] Fetching from DB")


def get_context_from_analysis(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, bin_anal, apk_id):
    """Get the context for APK/ZIP from analysis results"""
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
            'binary_analysis': bin_anal,
            'files': app_dic['files'],
            'certz': app_dic['certz'],
            'icon_hidden': app_dic['icon_hidden'],
            'icon_found': app_dic['icon_found'],
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
            'api': code_an_dic['api'],
            'findings': code_an_dic['findings'],
            'urls': code_an_dic['urls'],
            'domains': code_an_dic['domains'],
            'emails': code_an_dic['emails'],
            'strings': app_dic['strings'],
            'zipped': app_dic['zipped'],
            'mani': app_dic['mani'],
            'e_act': man_an_dic['exported_cnt']["act"],
            'e_ser': man_an_dic['exported_cnt']["ser"],
            'e_bro': man_an_dic['exported_cnt']["bro"],
            'e_cnt': man_an_dic['exported_cnt']["cnt"],
            'apkid': apk_id,
        }
        return context
    except:
        PrintException("[ERROR] Rendering to Template")


def update_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, bin_anal, apk_id):
    """Update an APK/ZIP DB entry"""
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
            BIN_ANALYSIS=bin_anal,
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ICON_HIDDEN=app_dic['icon_hidden'],
            ICON_FOUND=app_dic['icon_found'],
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
            API=code_an_dic['api'],
            DANG=code_an_dic['findings'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS=app_dic['strings'],
            ZIPPED=app_dic['zipped'],
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"],
            APK_ID=apk_id,
        )
    except:
        PrintException("[ERROR] Updating DB")


def create_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic, bin_anal, apk_id):
    """Create a new DB-Entry for APK/ZIP"""
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
            BIN_ANALYSIS=bin_anal,
            FILES=app_dic['files'],
            CERTZ=app_dic['certz'],
            ICON_HIDDEN=app_dic['icon_hidden'],
            ICON_FOUND=app_dic['icon_found'],
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
            API=code_an_dic['api'],
            DANG=code_an_dic['findings'],
            URLS=code_an_dic['urls'],
            DOMAINS=code_an_dic['domains'],
            EMAILS=code_an_dic['emails'],
            STRINGS=app_dic['strings'],
            ZIPPED=app_dic['zipped'],
            MANI=app_dic['mani'],
            EXPORTED_ACT=man_an_dic['exported_act'],
            E_ACT=man_an_dic['exported_cnt']["act"],
            E_SER=man_an_dic['exported_cnt']["ser"],
            E_BRO=man_an_dic['exported_cnt']["bro"],
            E_CNT=man_an_dic['exported_cnt']["cnt"],
            APK_ID=apk_id,
        )
        static_db.save()
    except:
        PrintException("[ERROR] Saving to DB")
