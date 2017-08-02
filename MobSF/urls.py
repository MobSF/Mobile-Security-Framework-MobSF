from django.conf.urls import url
import MobSF.views
import MobSF.rest_api
import APITester.views
import DynamicAnalyzer.views.android.android_dynamic
import DynamicAnalyzer.views.android_standalone
import StaticAnalyzer.views.android.static_analyzer
import StaticAnalyzer.views.android.java
import StaticAnalyzer.views.android.smali
import StaticAnalyzer.views.android.view_source
import StaticAnalyzer.views.android.manifest_view
import StaticAnalyzer.views.android.find
import StaticAnalyzer.views.ios.static_analyzer
import StaticAnalyzer.views.shared_func
import StaticAnalyzer.views.windows
import StaticAnalyzer.tests
from MobSF import utils


urlpatterns = [
    # Examples:
    url(r'^$', MobSF.views.index),
    url(r'^upload/$', MobSF.views.upload),
    url(r'^download/', MobSF.views.download),
    url(r'^about/$', MobSF.views.about),
    url(r'^recent_scans/$', MobSF.views.recent_scans),
    url(r'^delete_scan/$', MobSF.views.delete_scan),
    url(r'^search/$', MobSF.views.search),
    url(r'^error/$', MobSF.views.error),
    url(r'^not_found/$', MobSF.views.not_found),
    url(r'^zip_format/$', MobSF.views.zip_format),
    url(r'^mac_only/$', MobSF.views.mac_only),

    url(r'^StaticAnalyzer/$',
        StaticAnalyzer.views.android.static_analyzer.static_analyzer),
    url(r'^StaticAnalyzer_iOS/$',
        StaticAnalyzer.views.ios.static_analyzer.static_analyzer_ios),
    url(r'^StaticAnalyzer_Windows/$',
        StaticAnalyzer.views.windows.staticanalyzer_windows),
    url(r'^ViewFile/$', StaticAnalyzer.views.ios.static_analyzer.view_file),
    url(r'^ViewSource/$', StaticAnalyzer.views.android.view_source.run),
    url(r'^PDF/$', StaticAnalyzer.views.shared_func.pdf),
    url(r'^Smali/$', StaticAnalyzer.views.android.smali.run),
    url(r'^Java/$', StaticAnalyzer.views.android.java.run),
    url(r'^Find/$', StaticAnalyzer.views.android.find.run),
    url(r'^ManifestView/$', StaticAnalyzer.views.android.manifest_view.run),

    url(r'^DynamicAnalyzer/$',
        DynamicAnalyzer.views.android.android_dynamic.android_dynamic_analyzer),
    url(r'^GetEnv/$', DynamicAnalyzer.views.android.android_dynamic.get_env),
    url(r'^GetRes/$', DynamicAnalyzer.views.android.android_dynamic.get_res),
    url(r'^MobSFCA/$', DynamicAnalyzer.views.android.android_dynamic.mobsf_ca),
    url(r'^TakeScreenShot/$',
        DynamicAnalyzer.views.android.android_dynamic.take_screenshot),
    url(r'^ClipDump/$', DynamicAnalyzer.views.android.android_dynamic.clip_dump),
    url(r'^ExportedActivityTester/$',
        DynamicAnalyzer.views.android.android_dynamic.exported_activity_tester),
    url(r'^ActivityTester/$',
        DynamicAnalyzer.views.android.android_dynamic.activity_tester),
    url(r'^FinalTest/$', DynamicAnalyzer.views.android.android_dynamic.final_test),
    url(r'^DumpData/$', DynamicAnalyzer.views.android.android_dynamic.dump_data),
    url(r'^ExecuteADB/$', DynamicAnalyzer.views.android.android_dynamic.execute_adb),
    url(r'^Report/$', DynamicAnalyzer.views.android.android_dynamic.report),
    url(r'^View/$', DynamicAnalyzer.views.android.android_dynamic.view),
    url(r'^ScreenCast/$', DynamicAnalyzer.views.android.android_dynamic.screen_cast),
    url(r'^Touch/$', DynamicAnalyzer.views.android.android_dynamic.touch),

    url(r'^APIFuzzer/$', APITester.views.APIFuzzer),
    url(r'^StartScan/$', APITester.views.StartScan),
    url(r'^NoAPI/$', APITester.views.NoAPI),
    #REST API
    url(r'^api/v1/upload$', MobSF.rest_api.api_upload),
    url(r'^api/v1/scan$', MobSF.rest_api.api_scan),
    url(r'^api/v1/delete_scan$', MobSF.rest_api.api_delete_scan),
    url(r'^api/v1/download_pdf$', MobSF.rest_api.api_pdf_report),
    # Test
    url(r'^runtest/$', StaticAnalyzer.tests.start_test),
    url(r'^runapitest/$', StaticAnalyzer.tests.start_api_test),

]

utils.printMobSFverison()
