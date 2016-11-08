from django.conf.urls import url
import MobSF.views
import APITester.views
import DynamicAnalyzer.views.android
import DynamicAnalyzer.views.android_standalone
import StaticAnalyzer.views.android
import StaticAnalyzer.views.ios
import StaticAnalyzer.views.shared_func
import StaticAnalyzer.views.windows
from MobSF import utils


urlpatterns = [
    # Examples:
    url(r'^$', MobSF.views.index),
    url(r'^upload/$', MobSF.views.upload),
    url(r'^download/', MobSF.views.download),
    url(r'^about/$', MobSF.views.about),
    url(r'^recent_scans/$', MobSF.views.recent_scans),
    url(r'^search/$', MobSF.views.search),
    url(r'^error/$', MobSF.views.error),
    url(r'^not_found/$', MobSF.views.not_found),
    url(r'^zip_format/$', MobSF.views.zip_format),
    url(r'^mac_only/$', MobSF.views.mac_only),

    url(r'^StaticAnalyzer/$', StaticAnalyzer.views.android.StaticAnalyzer),
    url(r'^StaticAnalyzer_iOS/$', StaticAnalyzer.views.ios.StaticAnalyzer_iOS),
    url(r'^StaticAnalyzer_Windows/$', StaticAnalyzer.views.windows.staticanalyzer_windows),
    url(r'^ViewFile/$', StaticAnalyzer.views.ios.ViewFile),
    url(r'^ViewSource/$', StaticAnalyzer.views.android.ViewSource),
    url(r'^PDF/$', StaticAnalyzer.views.shared_func.PDF),
    url(r'^Smali/$', StaticAnalyzer.views.android.Smali),
    url(r'^Java/$', StaticAnalyzer.views.android.Java),
    url(r'^Find/$', StaticAnalyzer.views.android.Find),
    url(r'^ManifestView/$', StaticAnalyzer.views.android.ManifestView),

    url(r'^DynamicAnalyzer/$', DynamicAnalyzer.views.android.DynamicAnalyzer),
    url(r'^GetEnv/$', DynamicAnalyzer.views.android.GetEnv),
    url(r'^GetRes/$', DynamicAnalyzer.views.android.GetRes),
    url(r'^MobSFCA/$', DynamicAnalyzer.views.android.MobSFCA),
    url(r'^TakeScreenShot/$', DynamicAnalyzer.views.android.TakeScreenShot),
    url(r'^ClipDump/$', DynamicAnalyzer.views.android.clip_dump),
    url(r'^ExportedActivityTester/$',
        DynamicAnalyzer.views.android.ExportedActivityTester),
    url(r'^ActivityTester/$', DynamicAnalyzer.views.android.ActivityTester),
    url(r'^FinalTest/$', DynamicAnalyzer.views.android.FinalTest),
    url(r'^DumpData/$', DynamicAnalyzer.views.android.DumpData),
    url(r'^ExecuteADB/$', DynamicAnalyzer.views.android.ExecuteADB),
    url(r'^Report/$', DynamicAnalyzer.views.android.Report),
    url(r'^View/$', DynamicAnalyzer.views.android.View),
    url(r'^ScreenCast/$', DynamicAnalyzer.views.android.ScreenCast),
    url(r'^Touch/$', DynamicAnalyzer.views.android.Touch),

    url(r'^APIFuzzer/$', APITester.views.APIFuzzer),
    url(r'^StartScan/$', APITester.views.StartScan),
    url(r'^NoAPI/$', APITester.views.NoAPI),
]

utils.printMobSFverison()
