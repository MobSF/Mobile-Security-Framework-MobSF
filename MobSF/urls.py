from django.conf.urls import url

from DynamicAnalyzer.views.android import dynamic

from MobSF import utils
from MobSF.views import home
from MobSF.views.api import rest_api

from StaticAnalyzer import tests
from StaticAnalyzer.views import shared_func, windows
from StaticAnalyzer.views.android import find, java, manifest_view, smali
from StaticAnalyzer.views.android import static_analyzer as android_sa
from StaticAnalyzer.views.android import view_source
from StaticAnalyzer.views.ios import static_analyzer as ios_sa
from StaticAnalyzer.views.ios import view_source as io_view_source

urlpatterns = [
    # Examples:
    url(r'^$', home.index, name='home'),
    url(r'^upload/$', home.Upload.as_view),
    url(r'^download/', home.download),
    url(r'^about$', home.about, name='about'),
    url(r'^api_docs$', home.api_docs, name='api_docs'),
    url(r'^recent_scans/$', home.recent_scans, name='recent'),
    url(r'^delete_scan/$', home.delete_scan),
    url(r'^search$', home.search),
    url(r'^error/$', home.error, name='error'),
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
    # Windows
    url(r'^StaticAnalyzer_Windows/$', windows.staticanalyzer_windows),
    # Shared
    url(r'^PDF/$', shared_func.pdf),
    # We validate the hash sanity in the URL already
    url(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
        shared_func.compare_apps),

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
    url(r'^api/v1/scans$', rest_api.api_recent_scans),

    # Test
    url(r'^tests/$', tests.start_test),

]

utils.print_version()
