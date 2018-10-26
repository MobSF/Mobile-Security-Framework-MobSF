from django.conf.urls import url
from MobSF.views import (
    home,
)
from StaticAnalyzer.views.ios import (
    static_analyzer as ios_sa,
    view_source as io_view_source
)

from StaticAnalyzer.views.android import (
    static_analyzer as android_sa,
    view_source,
    smali,
    java,
    find,
    manifest_view
)

from StaticAnalyzer.views import (
    shared_func,
    windows
)

from MobSF.views.api import (
    rest_api
)

from DynamicAnalyzer.views.android import (
    dynamic
)

from StaticAnalyzer import tests

from MobSF import utils


urlpatterns = [
    # Examples:
    url(r'^$', home.index),
    url(r'^upload/$', home.Upload.as_view),
    url(r'^download/', home.download),
    url(r'^about$', home.about),
    url(r'^api_docs$', home.api_docs),
    url(r'^recent_scans/$', home.recent_scans),
    url(r'^delete_scan/$', home.delete_scan),
    url(r'^search$', home.search),
    url(r'^error/$', home.error),
    url(r'^not_found/$', home.not_found),
    url(r'^zip_format/$', home.zip_format),
    url(r'^mac_only/$', home.mac_only),

    # Static Analysis
    # Android
    url(r'^StaticAnalyzer/$', android_sa.static_analyzer),
    url(r'^ViewSource/$', view_source.run),
    url(r'^Smali/$', smali.run),
    url(r'^Java/$', java.run),
    url(r'^Find/$', find.run),
    url(r'^ManifestView/$', manifest_view.run),
    # IOS
    url(r'^StaticAnalyzer_iOS/$', ios_sa.static_analyzer_ios),
    url(r'^ViewFile/$', io_view_source.run),
    #Windows
    url(r'^StaticAnalyzer_Windows/$', windows.staticanalyzer_windows),
    #Shared
    url(r'^PDF/$', shared_func.pdf),

    # Android Dynamic Analysis
    url(r'^DynamicAnalyzer/$', dynamic.android_dynamic_analyzer),
    url(r'^GetEnv/$', dynamic.get_env),
    url(r'^GetRes/$', dynamic.get_res),
    url(r'^MobSFCA/$', dynamic.mobsf_ca),
    url(r'^TakeScreenShot/$', dynamic.take_screenshot),
    url(r'^ClipDump/$', dynamic.clip_dump),
    url(r'^ExportedActivityTester/$', dynamic.exported_activity_tester),
    url(r'^ActivityTester/$', dynamic.activity_tester),
    url(r'^FinalTest/$', dynamic.final_test),
    url(r'^DumpData/$', dynamic.dump_data),
    url(r'^ExecuteADB/$', dynamic.execute_adb),
    url(r'^Report/$', dynamic.report),
    url(r'^View/$', dynamic.view),
    url(r'^ScreenCast/$', dynamic.screen_cast),
    url(r'^Touch/$', dynamic.touch),
    url(r'^capfuzz$', dynamic.capfuzz_start),

    # REST API
    url(r'^api/v1/upload$', rest_api.api_upload),
    url(r'^api/v1/scan$', rest_api.api_scan),
    url(r'^api/v1/delete_scan$', rest_api.api_delete_scan),
    url(r'^api/v1/download_pdf$', rest_api.api_pdf_report),
    url(r'^api/v1/report_json$', rest_api.api_json_report),
    url(r'^api/v1/view_source$', rest_api.api_view_source),

    # Test
    url(r'^tests/$', tests.start_test),

]

utils.printMobSFverison()
