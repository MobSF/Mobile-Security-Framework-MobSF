from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    # Examples:
    url(r'^$', 'MobSF.views.index', name='index'),
    url(r'^Upload/$', 'MobSF.views.Upload', name='Upload'),
    url(r'^about/$', 'MobSF.views.about', name='about'),
    url(r'^error/$', 'MobSF.views.error', name='error'),
    url(r'^features/$', 'MobSF.views.features', name='features'),
    url(r'^ZIP_FORMAT/$', 'MobSF.views.ZIP_FORMAT', name='ZIP_FORMAT'),
    url(r'^MAC_ONLY/$', 'MobSF.views.MAC_ONLY', name='MAC_ONLY'),
    url(r'^StaticAnalyzer/$', 'StaticAnalyzer.views.StaticAnalyzer', name='StaticAnalyzer'),
    url(r'^StaticAnalyzer_iOS/$', 'StaticAnalyzer.views.StaticAnalyzer_iOS', name='StaticAnalyzer_iOS'),
    url(r'^ViewSource/$', 'StaticAnalyzer.views.ViewSource', name='ViewSource'),
    url(r'^PDF/$', 'StaticAnalyzer.views.PDF', name='PDF'),
    url(r'^ViewFile/$', 'StaticAnalyzer.views.ViewFile', name='ViewFile'),
    url(r'^Smali/$', 'StaticAnalyzer.views.Smali', name='Smali'),
    url(r'^Java/$', 'StaticAnalyzer.views.Java', name='Java'),
    url(r'^Search/$', 'StaticAnalyzer.views.Search', name='Search'),
    url(r'^ManifestView/$', 'StaticAnalyzer.views.ManifestView', name='ManifestView'),
    url(r'^DynamicAnalyzer/$', 'DynamicAnalyzer.views.DynamicAnalyzer', name='DynamicAnalyzer'),
    url(r'^GetEnv/$', 'DynamicAnalyzer.views.GetEnv', name='GetEnv'),
    url(r'^TakeScreenShot/$', 'DynamicAnalyzer.views.TakeScreenShot', name='TakeScreenShot'),
    url(r'^ExportedActivityTester/$', 'DynamicAnalyzer.views.ExportedActivityTester', name='ExportedActivityTester'),
    url(r'^ActivityTester/$', 'DynamicAnalyzer.views.ActivityTester', name='ActivityTester'),
    url(r'^FinalTest/$', 'DynamicAnalyzer.views.FinalTest', name='FinalTest'),
    url(r'^DumpData/$', 'DynamicAnalyzer.views.DumpData', name='DumpData'),
    url(r'^ExecuteADB/$', 'DynamicAnalyzer.views.ExecuteADB', name='ExecuteADB'),
    url(r'^Report/$', 'DynamicAnalyzer.views.Report', name='Report'),
    url(r'^View/$', 'DynamicAnalyzer.views.View', name='View'),
    #url(r'^admin/', include(admin.site.urls)),
]



