from django.conf.urls import url

from mobsf.DynamicAnalyzer.views.android import dynamic_analyzer as dz
from mobsf.DynamicAnalyzer.views.android import (
    operations,
    report,
    tests_common,
    tests_frida,
)
from mobsf.MobSF import utils
from mobsf.MobSF.views import home
from mobsf.MobSF.views.api import api_static_analysis as api_sz
from mobsf.MobSF.views.api import api_dynamic_analysis as api_dz
from mobsf.StaticAnalyzer import tests
from mobsf.StaticAnalyzer.views import shared_func
from mobsf.StaticAnalyzer.views.android import (
    find,
    generate_downloads,
    manifest_view,
    source_tree,
    view_source,
)
from mobsf.StaticAnalyzer.views.windows import windows
from mobsf.StaticAnalyzer.views.android import static_analyzer as android_sa
from mobsf.StaticAnalyzer.views.ios import static_analyzer as ios_sa
from mobsf.StaticAnalyzer.views.ios import view_source as io_view_source

from . import settings


urlpatterns = [
    # REST API
    # Static Analysis
    url(r'^api/v1/upload$', api_sz.api_upload),
    url(r'^api/v1/scan$', api_sz.api_scan),
    url(r'^api/v1/delete_scan$', api_sz.api_delete_scan),
    url(r'^api/v1/download_pdf$', api_sz.api_pdf_report),
    url(r'^api/v1/report_json$', api_sz.api_json_report),
    url(r'^api/v1/view_source$', api_sz.api_view_source,
        name='api_view_source'),
    url(r'^api/v1/scans$', api_sz.api_recent_scans),
    url(r'^api/v1/compare$', api_sz.api_compare),
    # Dynamic Analysis
    url(r'^api/v1/dynamic/get_apps$', api_dz.api_get_apps),
    url(r'^api/v1/dynamic/start_analysis$', api_dz.api_start_analysis),
    url(r'^api/v1/dynamic/stop_analysis$', api_dz.api_stop_analysis),
    url(r'^api/v1/dynamic/report_json$', api_dz.api_dynamic_report),
    url(r'^api/v1/dynamic/view_source$', api_dz.api_dynamic_view_file),
    # Android Specific
    url(r'^api/v1/android/logcat$', api_dz.api_logcat),
    url(r'^api/v1/android/mobsfy$', api_dz.api_mobsfy),
    url(r'^api/v1/android/adb_command$', api_dz.api_adb_execute),
    url(r'^api/v1/android/root_ca$', api_dz.api_root_ca),
    url(r'^api/v1/android/activity$', api_dz.api_api_tester),
    # Frida
    url(r'^api/v1/frida/instrument$', api_dz.api_instrument),
    url(r'^api/v1/frida/api_monitor$', api_dz.api_api_monitor),
    url(r'^api/v1/frida/logs$', api_dz.api_frida_logs),
    url(r'^api/v1/frida/list_scripts$', api_dz.api_list_frida_scripts),
    url(r'^api/v1/frida/get_script$', api_dz.api_get_script),
]
if settings.API_ONLY == '0':
    urlpatterns.extend([
        # General
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

        # Static Analysis
        # Android
        url(r'^static_analyzer/$', android_sa.static_analyzer),
        # Remove this is version 4/5
        url(r'^source_code/$', source_tree.run, name='tree_view'),
        url(r'^view_file/$', view_source.run, name='view_source'),
        url(r'^find/$', find.run, name='find_files'),
        url(r'^generate_downloads/$', generate_downloads.run),
        url(r'^manifest_view/$', manifest_view.run),
        # IOS
        url(r'^static_analyzer_ios/$', ios_sa.static_analyzer_ios),
        url(r'^view_file_ios/$', io_view_source.run),
        # Windows
        url(r'^static_analyzer_windows/$', windows.staticanalyzer_windows),
        # Shared
        url(r'^pdf/$', shared_func.pdf),
        # App Compare
        url(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
            shared_func.compare_apps),

        # Dynamic Analysis
        url(r'^dynamic_analysis/$',
            dz.dynamic_analysis,
            name='dynamic'),
        url(r'^android_dynamic/(?P<checksum>[0-9a-f]{32})$',
            dz.dynamic_analyzer,
            name='dynamic_analyzer'),
        url(r'^httptools$',
            dz.httptools_start,
            name='httptools'),
        url(r'^logcat/$', dz.logcat),
        # Android Operations
        url(r'^mobsfy/$', operations.mobsfy),
        url(r'^screenshot/$', operations.take_screenshot),
        url(r'^execute_adb/$', operations.execute_adb),
        url(r'^screen_cast/$', operations.screen_cast),
        url(r'^touch_events/$', operations.touch),
        url(r'^get_component/$', operations.get_component),
        url(r'^mobsf_ca/$', operations.mobsf_ca),
        # Dynamic Tests
        url(r'^activity_tester/$', tests_common.activity_tester),
        url(r'^download_data/$', tests_common.download_data),
        url(r'^collect_logs/$', tests_common.collect_logs),
        # Frida
        url(r'^frida_instrument/$', tests_frida.instrument),
        url(r'^live_api/$', tests_frida.live_api),
        url(r'^frida_logs/$', tests_frida.frida_logs),
        url(r'^list_frida_scripts/$', tests_frida.list_frida_scripts),
        url(r'^get_script/$', tests_frida.get_script),
        # Report
        url(r'^dynamic_report/(?P<checksum>[0-9a-f]{32})$',
            report.view_report),
        url(r'^dynamic_view_file/$', report.view_file),
        # Test
        url(r'^tests/$', tests.start_test),
    ])

utils.print_version()
