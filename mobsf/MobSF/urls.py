from django.urls import re_path

from mobsf.DynamicAnalyzer.views.common import (
    device,
    frida,
)
from mobsf.DynamicAnalyzer.views.android import dynamic_analyzer as dz
from mobsf.DynamicAnalyzer.views.android import (
    operations,
    report,
    tests_common,
    tests_frida,
)
from mobsf.DynamicAnalyzer.views.ios import dynamic_analyzer as idz
from mobsf.DynamicAnalyzer.views.ios import (
    corellium_instance as instance,
    report as ios_view_report,
    tests_frida as ios_tests_frida,
)
from mobsf.MobSF import utils
from mobsf.MobSF.views import home
from mobsf.MobSF.views.api import api_static_analysis as api_sz
from mobsf.MobSF.views.api import api_dynamic_analysis as api_dz
from mobsf.StaticAnalyzer import tests
from mobsf.StaticAnalyzer.views.common import (
    appsec,
    pdf,
    shared_func,
    suppression,
)
from mobsf.StaticAnalyzer.views.android import (
    find,
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
    re_path(r'^api/v1/scorecard$', api_sz.api_scorecard),
    # Static Suppression
    re_path(r'^api/v1/suppress_by_rule$', api_sz.api_suppress_by_rule_id),
    re_path(r'^api/v1/suppress_by_files$', api_sz.api_suppress_by_files),
    re_path(r'^api/v1/list_suppressions$', api_sz.api_list_suppressions),
    re_path(r'^api/v1/delete_suppression$', api_sz.api_delete_suppression),
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
    re_path(r'^api/v1/frida/get_dependencies$', api_dz.api_get_dependencies),
    # Shared
    re_path(r'^api/v1/frida/list_scripts$', api_dz.api_list_frida_scripts),
    re_path(r'^api/v1/frida/get_script$', api_dz.api_get_script),
]
if settings.API_ONLY == '0':
    urlpatterns.extend([
        # General
        re_path(r'^$', home.index, name='home'),
        re_path(r'^upload/$', home.Upload.as_view),
        re_path(r'^download/', home.download, name='download'),
        re_path(r'^download_scan/', home.download_apk, name='download_scan'),
        re_path(r'^generate_downloads/$',
                home.generate_download,
                name='generate_downloads'),
        re_path(r'^about$', home.about, name='about'),
        re_path(r'^donate$', home.donate, name='donate'),
        re_path(r'^api_docs$', home.api_docs, name='api_docs'),
        re_path(r'^recent_scans/$', home.recent_scans, name='recent'),
        re_path(r'^delete_scan/$', home.delete_scan, name='delete_scan'),
        re_path(r'^search$', home.search),
        re_path(r'^error/$', home.error, name='error'),
        re_path(r'^not_found/$', home.not_found),
        re_path(r'^zip_format/$', home.zip_format),
        re_path(r'^dynamic_analysis/$', home.dynamic_analysis, name='dynamic'),

        # Static Analysis
        # Android
        re_path(r'^static_analyzer/(?P<checksum>[0-9a-f]{32})/$',
                android_sa.static_analyzer,
                name='static_analyzer'),
        # Remove this is version 4/5
        re_path(r'^source_code/$', source_tree.run, name='tree_view'),
        re_path(r'^view_file/$', view_source.run, name='view_source'),
        re_path(r'^find/$', find.run, name='find_files'),
        re_path(r'^manifest_view/(?P<checksum>[0-9a-f]{32})/$',
                manifest_view.run,
                name='manifest_view'),
        # IOS
        re_path(r'^static_analyzer_ios/(?P<checksum>[0-9a-f]{32})/$',
                ios_sa.static_analyzer_ios,
                name='static_analyzer_ios'),
        re_path(r'^view_file_ios/$',
                io_view_source.run,
                name='view_file_ios'),
        # Windows
        re_path(r'^static_analyzer_windows/(?P<checksum>[0-9a-f]{32})/$',
                windows.staticanalyzer_windows,
                name='static_analyzer_windows'),
        # Shared
        re_path(r'^pdf/(?P<checksum>[0-9a-f]{32})/$', pdf.pdf, name='pdf'),
        re_path(r'^appsec_dashboard/(?P<checksum>[0-9a-f]{32})/$',
                appsec.appsec_dashboard,
                name='appsec_dashboard'),
        # Suppression
        re_path(r'^suppress_by_rule/$',
                suppression.suppress_by_rule_id,
                name='suppress_by_rule'),
        re_path(r'^suppress_by_files/$',
                suppression.suppress_by_files,
                name='suppress_by_files'),
        re_path(r'^list_suppressions/$',
                suppression.list_suppressions,
                name='list_suppressions'),
        re_path(r'^delete_suppression/$',
                suppression.delete_suppression,
                name='delete_suppression'),
        # App Compare
        re_path(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
                shared_func.compare_apps),

        # Dynamic Analysis
        re_path(r'^android/dynamic_analysis/$',
                dz.android_dynamic_analysis,
                name='dynamic_android'),
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
        re_path(r'^mobsfy/$', operations.mobsfy, name='mobsfy'),
        re_path(r'^screenshot/$', operations.take_screenshot),
        re_path(r'^execute_adb/$', operations.execute_adb),
        re_path(r'^screen_cast/$',
                operations.screen_cast,
                name='screen_cast'),
        re_path(r'^touch_events/$',
                operations.touch,
                name='android_touch'),
        re_path(r'^get_component/$', operations.get_component),
        re_path(r'^mobsf_ca/$', operations.mobsf_ca),
        re_path(r'^global_proxy/$', operations.global_proxy),
        # Dynamic Tests
        re_path(r'^activity_tester/$', tests_common.activity_tester),
        re_path(r'^start_activity/$',
                tests_common.start_activity,
                name='start_activity'),
        re_path(r'^download_data/$', tests_common.download_data),
        re_path(r'^collect_logs/$', tests_common.collect_logs),
        re_path(r'^tls_tests/$', tests_common.tls_tests),
        # Frida
        re_path(r'^frida_instrument/$',
                tests_frida.instrument,
                name='android_instrument'),
        re_path(r'^live_api/$',
                tests_frida.live_api,
                name='live_api'),
        re_path(r'^frida_logs/$',
                frida.frida_logs,
                name='frida_logs'),
        re_path(r'^get_dependencies/$', tests_frida.get_runtime_dependencies),
        # Report
        re_path(r'^dynamic_report/(?P<checksum>[0-9a-f]{32})$',
                report.view_report,
                name='dynamic_report'),
        # Shared
        re_path(r'^list_frida_scripts/$',
                frida.list_frida_scripts,
                name='list_frida_scripts'),
        re_path(r'^get_script/$',
                frida.get_script,
                name='get_script'),
        re_path(r'^dynamic_view_file/$',
                device.view_file,
                name='dynamic_view_file'),
        # iOS Dynamic Analysis
        re_path(r'^ios/dynamic_analysis/$',
                idz.dynamic_analysis,
                name='dynamic_ios'),
        re_path(r'^ios/create_vm_instance/$',
                instance.create_vm_instance,
                name='create_vm_instance'),
        re_path(r'^ios/get_supported_models/$',
                instance.get_supported_models,
                name='get_supported_models'),
        re_path(r'^ios/get_supported_os/$',
                instance.get_supported_os,
                name='get_supported_os'),
        re_path(r'^ios/start_instance/$',
                instance.start_instance,
                name='start_instance'),
        re_path(r'^ios/stop_instance/$',
                instance.stop_instance,
                name='stop_instance'),
        re_path(r'^ios/unpause_instance/$',
                instance.unpause_instance,
                name='unpause_instance'),
        re_path(r'^ios/reboot_instance/$',
                instance.reboot_instance,
                name='reboot_instance'),
        re_path(r'^ios/destroy_instance/$',
                instance.destroy_instance,
                name='destroy_instance'),
        re_path(r'^ios/list_apps/$',
                instance.list_apps,
                name='list_apps'),
        re_path(r'^ios/setup_environment/(?P<checksum>[0-9a-f]{32})$',
                instance.setup_environment,
                name='setup_environment'),
        re_path(r'^ios/dynamic_analyzer/$',
                idz.dynamic_analyzer,
                name='dynamic_analyzer_ios'),
        re_path(r'^ios/run_app/$',
                instance.run_app,
                name='run_app'),
        re_path(r'^ios/remove_app/$',
                instance.remove_app,
                name='remove_app'),
        re_path(r'^ios/take_screenshot/$',
                instance.take_screenshot,
                name='take_screenshot'),
        re_path(r'^ios/network_capture/$',
                instance.network_capture,
                name='network_capture'),
        re_path(r'^ios/live_pcap_download/$',
                instance.live_pcap_download,
                name='ios_live_pcap_download'),
        re_path(r'^ios/ssh_execute/$',
                instance.ssh_execute,
                name='ssh_execute'),
        re_path(r'^ios/upload_file/$',
                instance.upload_file,
                name='upload_file'),
        re_path(r'^ios/download_file/$',
                instance.download_file,
                name='download_file'),
        re_path(r'^ios/touch/$',
                instance.touch,
                name='ios_touch'),
        re_path(r'^ios/get_container_path/$',
                instance.get_container_path,
                name='get_container_path'),
        re_path(r'^ios/system_logs/$',
                instance.system_logs,
                name='ios_system_logs'),
        re_path(r'^ios/download_data/(?P<bundle_id>([\w]*\.)+[\w-]{2,155})$',
                instance.download_data,
                name='ios_download_data'),
        re_path(r'^ios/instrument/$',
                ios_tests_frida.ios_instrument,
                name='ios_instrument'),
        re_path(r'^ios/view_report/(?P<bundle_id>([\w]*\.)+[\w-]{2,155})$',
                ios_view_report.ios_view_report,
                name='ios_view_report'),

        # Test
        re_path(r'^tests/$', tests.start_test),
    ])

utils.print_version()
