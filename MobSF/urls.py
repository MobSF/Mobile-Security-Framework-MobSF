from django.conf.urls import url
import MobSF.views
import MobSF.rest_api
import DynamicAnalyzer.views.android.dynamic
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
    url(r'^about$', MobSF.views.about),
    url(r'^api_docs$', MobSF.views.api_docs),
    url(r'^recent_scans$', MobSF.views.recent_scans),
    url(r'^delete_scan/$', MobSF.views.delete_scan),
    url(r'^search$', MobSF.views.search),
    url(r'^error/$', MobSF.views.error),
    url(r'^not_found/$', MobSF.views.not_found),
    url(r'^zip_format/$', MobSF.views.zip_format),
    url(r'^mac_only/$', MobSF.views.mac_only),

    # Android Static Analysis
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

    # Android Dynamic Analysis
    url(r'^DynamicAnalyzer/$',
        DynamicAnalyzer.views.android.dynamic.android_dynamic_analyzer),
    url(r'^GetEnv/$', DynamicAnalyzer.views.android.dynamic.get_env),
    url(r'^GetRes/$', DynamicAnalyzer.views.android.dynamic.get_res),
    url(r'^MobSFCA/$', DynamicAnalyzer.views.android.dynamic.mobsf_ca),
    url(r'^TakeScreenShot/$',
        DynamicAnalyzer.views.android.dynamic.take_screenshot),
    url(r'^ClipDump/$', DynamicAnalyzer.views.android.dynamic.clip_dump),
    url(r'^ExportedActivityTester/$',
        DynamicAnalyzer.views.android.dynamic.exported_activity_tester),
    url(r'^ActivityTester/$',
        DynamicAnalyzer.views.android.dynamic.activity_tester),
    url(r'^FinalTest/$', DynamicAnalyzer.views.android.dynamic.final_test),
    url(r'^DumpData/$', DynamicAnalyzer.views.android.dynamic.dump_data),
    url(r'^ExecuteADB/$', DynamicAnalyzer.views.android.dynamic.execute_adb),
    url(r'^Report/$', DynamicAnalyzer.views.android.dynamic.report),
    url(r'^View/$', DynamicAnalyzer.views.android.dynamic.view),
    url(r'^ScreenCast/$', DynamicAnalyzer.views.android.dynamic.screen_cast),
    url(r'^Touch/$', DynamicAnalyzer.views.android.dynamic.touch),
    url(r'^capfuzz$', DynamicAnalyzer.views.android.dynamic.capfuzz_start),

    # REST API
    url(r'^api/v1/upload$', MobSF.rest_api.api_upload),
    url(r'^api/v1/scan$', MobSF.rest_api.api_scan),
    url(r'^api/v1/delete_scan$', MobSF.rest_api.api_delete_scan),
    url(r'^api/v1/download_pdf$', MobSF.rest_api.api_pdf_report),
    url(r'^api/v1/report_json$', MobSF.rest_api.api_json_report),

    # Test
    url(r'^runtest/$', StaticAnalyzer.tests.start_test),
    url(r'^runapitest/$', StaticAnalyzer.tests.start_api_test),

]

utils.printMobSFverison()
