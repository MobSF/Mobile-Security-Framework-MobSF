from django.urls import re_path

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
    re_path(r'^api/v1/upload$', api_sz.api_upload),
    re_path(r'^api/v1/scan$', api_sz.api_scan),
    re_path(r'^api/v1/delete_scan$', api_sz.api_delete_scan),
    re_path(r'^api/v1/download_pdf$', api_sz.api_pdf_report),
    re_path(r'^api/v1/report_json$', api_sz.api_json_report),
    re_path(r'^api/v1/view_source$', api_sz.api_view_source,
            name='api_view_source'),
    re_path(r'^api/v1/scans$', api_sz.api_recent_scans),
    re_path(r'^api/v1/compare$', api_sz.api_compare),
    # Dynamic Analysis
    re_path(r'^api/v1/dynamic/get_apps$', api_dz.api_get_apps),
    re_path(r'^api/v1/dynamic/start_analysis$', api_dz.api_start_analysis),
    re_path(r'^api/v1/dynamic/stop_analysis$', api_dz.api_stop_analysis),
    re_path(r'^api/v1/dynamic/report_json$', api_dz.api_dynamic_report),
    re_path(r'^api/v1/dynamic/view_source$', api_dz.api_dynamic_view_file),
    # Android Specific
    re_path(r'^api/v1/android/logcat$', api_dz.api_logcat),
    re_path(r'^api/v1/android/mobsfy$', api_dz.api_mobsfy),
    re_path(r'^api/v1/android/adb_command$', api_dz.api_adb_execute),
    re_path(r'^api/v1/android/root_ca$', api_dz.api_root_ca),
    re_path(r'^api/v1/android/global_proxy$', api_dz.api_global_proxy),
    re_path(r'^api/v1/android/activity$', api_dz.api_act_tester),
    re_path(r'^api/v1/android/start_activity$', api_dz.api_start_activity),
    re_path(r'^api/v1/android/tls_tests$', api_dz.api_tls_tester),
    # Frida
    re_path(r'^api/v1/frida/instrument$', api_dz.api_instrument),
    re_path(r'^api/v1/frida/api_monitor$', api_dz.api_api_monitor),
    re_path(r'^api/v1/frida/logs$', api_dz.api_frida_logs),
    re_path(r'^api/v1/frida/list_scripts$', api_dz.api_list_frida_scripts),
    re_path(r'^api/v1/frida/get_script$', api_dz.api_get_script),
    re_path(r'^api/v1/frida/get_dependencies$', api_dz.api_get_dependencies),
]
if settings.API_ONLY == '0':
    urlpatterns.extend([
        # General
        re_path(r'^$', home.index, name='home'),
        re_path(r'^upload/$', home.Upload.as_view),
        re_path(r'^download/', home.download),
        re_path(r'^download_scan/', home.download_apk),
        re_path(r'^about$', home.about, name='about'),
        re_path(r'^api_docs$', home.api_docs, name='api_docs'),
        re_path(r'^recent_scans/$', home.recent_scans, name='recent'),
        re_path(r'^delete_scan/$', home.delete_scan),
        re_path(r'^search$', home.search),
        re_path(r'^error/$', home.error, name='error'),
        re_path(r'^not_found/$', home.not_found),
        re_path(r'^zip_format/$', home.zip_format),

        # Static Analysis
        # Android
        re_path(r'^static_analyzer/$', android_sa.static_analyzer),
        # Remove this is version 4/5
        re_path(r'^source_code/$', source_tree.run, name='tree_view'),
        re_path(r'^view_file/$', view_source.run, name='view_source'),
        re_path(r'^find/$', find.run, name='find_files'),
        re_path(r'^generate_downloads/$', generate_downloads.run),
        re_path(r'^manifest_view/$', manifest_view.run),
        # IOS
        re_path(r'^static_analyzer_ios/$', ios_sa.static_analyzer_ios),
        re_path(r'^view_file_ios/$', io_view_source.run),
        # Windows
        re_path(r'^static_analyzer_windows/$', windows.staticanalyzer_windows),
        # Shared
        re_path(r'^pdf/$', shared_func.pdf),
        # App Compare
        re_path(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
                shared_func.compare_apps),

        # Dynamic Analysis
        re_path(r'^dynamic_analysis/$',
                dz.dynamic_analysis,
                name='dynamic'),
        re_path(r'^android_dynamic/(?P<checksum>[0-9a-f]{32})$',
                dz.dynamic_analyzer,
                name='dynamic_analyzer'),
        re_path(r'^httptools$',
                dz.httptools_start,
                name='httptools'),
        re_path(r'^logcat/$', dz.logcat),
        re_path(r'^static_scan/(?P<checksum>[0-9a-f]{32})$',
                dz.trigger_static_analysis,
                name='static_scan'),
        # Android Operations
        re_path(r'^run_apk/$', operations.run_apk),
        re_path(r'^mobsfy/$', operations.mobsfy),
        re_path(r'^screenshot/$', operations.take_screenshot),
        re_path(r'^execute_adb/$', operations.execute_adb),
        re_path(r'^screen_cast/$', operations.screen_cast),
        re_path(r'^touch_events/$', operations.touch),
        re_path(r'^get_component/$', operations.get_component),
        re_path(r'^mobsf_ca/$', operations.mobsf_ca),
        re_path(r'^global_proxy/$', operations.global_proxy),
        # Dynamic Tests
        re_path(r'^activity_tester/$', tests_common.activity_tester),
        re_path(r'^start_activity/$', tests_common.start_activity),
        re_path(r'^download_data/$', tests_common.download_data),
        re_path(r'^collect_logs/$', tests_common.collect_logs),
        re_path(r'^tls_tests/$', tests_common.tls_tests),
        # Frida
        re_path(r'^frida_instrument/$', tests_frida.instrument),
        re_path(r'^live_api/$', tests_frida.live_api),
        re_path(r'^frida_logs/$', tests_frida.frida_logs),
        re_path(r'^list_frida_scripts/$', tests_frida.list_frida_scripts),
        re_path(r'^get_script/$', tests_frida.get_script),
        re_path(r'^get_dependencies/$', tests_frida.get_runtime_dependencies),
        # Report
        re_path(r'^dynamic_report/(?P<checksum>[0-9a-f]{32})$',
                report.view_report),
        re_path(r'^dynamic_view_file/$', report.view_file),
        # Test
        re_path(r'^tests/$', tests.start_test),
    ])

utils.print_version()
