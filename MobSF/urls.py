from django.conf.urls import url
import MobSF.views
import APITester.views
import DynamicAnalyzer.views.android
import StaticAnalyzer.views.android
import StaticAnalyzer.views.ios
import StaticAnalyzer.views.shared_func
import StaticAnalyzer.views.windows

urlpatterns = [
    # Examples:
    url(r'^$',MobSF.views.index),
    url(r'^Upload/$', MobSF.views.Upload),
    url(r'^download/', MobSF.views.Download),
    url(r'^about/$', MobSF.views.about),
    url(r'^RecentScans/$', MobSF.views.RecentScans),
    url(r'^Search/$', MobSF.views.Search),
    url(r'^error/$', MobSF.views.error),
    url(r'^NotFound/$', MobSF.views.NotFound),
    url(r'^ZIP_FORMAT/$', MobSF.views.ZIP_FORMAT),
    url(r'^MAC_ONLY/$', MobSF.views.MAC_ONLY),

    url(r'^StaticAnalyzer/$', StaticAnalyzer.views.android.StaticAnalyzer),
    url(r'^StaticAnalyzer_iOS/$', StaticAnalyzer.views.ios.StaticAnalyzer_iOS),
    url(r'^StaticAnalyzer_Windows/$', StaticAnalyzer.views.windows.StaticAnalyzer_Windows),
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
    url(r'^ExportedActivityTester/$', DynamicAnalyzer.views.android.ExportedActivityTester),
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
