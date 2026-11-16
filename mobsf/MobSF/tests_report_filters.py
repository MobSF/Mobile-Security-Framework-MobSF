# -*- coding: utf_8 -*-
"""Tests for report template filters and includes."""
from unittest import mock

from django.template import Context, Template
from django.test import SimpleTestCase, TestCase

import mobsf.MobSF.views.home  # noqa: F401  registers report filters
from mobsf.MobSF.utils import (
    has_ofac,
    is_http_url,
    malware_first,
)
from mobsf.MobSF.views.home import (
    _suppression_revisions,
    _tracker_count,
)
from mobsf.StaticAnalyzer.models import SuppressFindings
from mobsf.StaticAnalyzer.views.common.appsec import appsec_summary
from mobsf.StaticAnalyzer.views.common.technology import (
    detect_technologies,
)

DOMAINS = {
    'b.example.com': {'bad': 'no', 'ofac': False},
    'a.example.com': {'bad': 'no'},
    'z.example.com': {'bad': 'yes', 'ofac': True},
}


class ReportFilterTests(SimpleTestCase):

    def test_malware_first(self):
        order = [d for d, _ in malware_first(DOMAINS)]
        self.assertEqual(
            order, ['z.example.com', 'a.example.com', 'b.example.com'])
        self.assertEqual(malware_first(None), [])

    def test_has_ofac(self):
        self.assertTrue(has_ofac(DOMAINS))
        self.assertFalse(has_ofac({'a': {'ofac': False}, 'b': 'x'}))
        self.assertFalse(has_ofac([]))

    def test_is_http_url(self):
        self.assertTrue(is_http_url('https://example.com/privacy'))
        self.assertTrue(is_http_url(' HTTP://example.com'))
        self.assertFalse(is_http_url('javascript:alert(1)'))
        self.assertFalse(is_http_url('//example.com'))
        self.assertFalse(is_http_url(None))

    def test_store_links_reject_script_urls(self):
        tpl = Template("{% include 'base/playstore_card.html' %}")
        html = tpl.render(Context({'playstore_details': {
            'title': '<b>x</b>',
            'url': 'javascript:alert(1)',
            'privacyPolicy': 'javascript:alert(2)',
        }}))
        self.assertNotIn('href="javascript:', html)
        self.assertNotIn('<b>x</b>', html)
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', html)

    def test_score_ring(self):
        tpl = Template("{% include 'base/score_ring.html' %}")
        html = tpl.render(Context({
            'appsec': {'security_score': 35},
            'md5': 'c8a0f01a5d0ed6406fd2c553fccdaefa',
            'store': {'icon': 'javascript:alert(1)'},
            'icon_path': 'c8a0f01a5d0ed6406fd2c553fccdaefa-icon.png',
        }))
        self.assertIn('risk-high', html)
        self.assertIn('stroke-dasharray="35 100"', html)
        self.assertIn('/appsec_dashboard/c8a0f01a5d0ed6406fd2c553fccdaefa/',
                      html)
        self.assertNotIn('javascript:', html)
        self.assertIn('/download/c8a0f01a5d0ed6406fd2c553fccdaefa-icon.png',
                      html)

    def test_android_technologies(self):
        ctx = {
            'files': [
                'classes.dex',
                'kotlin/collections/collections.kotlin_builtins',
                'lib/arm64-v8a/libhermes.so',
                'lib/arm64-v8a/libreactnativejni.so',
                'lib/x86_64/libreactnativejni.so',
                'lib/evil/libfoo.so',
                'lib/arm64-v8a/libfrida-gadget.so',
                'META-INF/androidx.compose.runtime_runtime.version',
                'META-INF/com/google/firebase/firebase-common.properties',
            ],
            'apkid': {
                'classes.dex': {'compiler': ['r8'], 'obfuscator': ['DexGuard']},
                'classes2.dex': {
                    'compiler': ['unknown (please file detection issue!)']},
                'x.apk': {'packer': ['DexGuard']},
            },
            'js_analysis': {'frameworks': ['React Native (Hermes)', 'Expo']},
        }
        tech = {g['label']: g['items']
                for g in detect_technologies(ctx, 'android')}
        self.assertEqual(
            tech['Languages'], ['Java', 'Kotlin', 'JavaScript', 'C/C++'])
        self.assertEqual(tech['Frameworks'], [
            'React Native', 'Hermes', 'Expo', 'Jetpack Compose', 'Firebase'])
        self.assertEqual(tech['Native ABIs'], ['arm64-v8a', 'x86_64'])
        self.assertEqual(tech['Build'], ['r8'])
        self.assertEqual(tech['Protection'], ['DexGuard'])
        self.assertEqual(tech['Instrumentation'], ['Frida Gadget'])

    def test_android_cross_platform_frameworks(self):
        ctx = {'files': [
            'classes.dex',
            'lib/arm64-v8a/libflutter.so',
            'lib/arm64-v8a/libapp.so',
            'lib/armeabi-v7a/libunity.so',
            'lib/armeabi-v7a/libil2cpp.so',
            'lib/x86/libmonodroid.so',
        ]}
        tech = {g['label']: g['items']
                for g in detect_technologies(ctx, 'android')}
        self.assertEqual(tech['Frameworks'], [
            'Flutter', 'Xamarin / .NET', 'Unity', 'Unity IL2CPP'])
        self.assertEqual(tech['Languages'], ['Java', 'Dart', 'C#', 'C/C++'])

    def test_ios_technologies(self):
        ctx = {
            'app_type': 'Swift, Objective-C',
            'files': [
                'Runner.app/Frameworks/Flutter.framework/Flutter',
                'Runner.app/Frameworks/App.framework/App',
                'Runner.app/GoogleService-Info.plist',
            ],
        }
        tech = {g['label']: g['items']
                for g in detect_technologies(ctx, 'ios')}
        self.assertEqual(tech['Languages'], ['Swift', 'Objective-C', 'Dart'])
        self.assertEqual(tech['Frameworks'], ['Flutter', 'Firebase'])
        self.assertEqual(tech['Build'], ['2 embedded frameworks'])

    def test_technologies_ignore_bad_input(self):
        ctx = {'files': [None, 3, {'x': 1}], 'apkid': ['x'],
               'js_analysis': 'oops'}
        self.assertEqual(detect_technologies(ctx, 'android'), [])
        self.assertEqual(detect_technologies({}, 'ios'), [])

    def test_check_cell_escapes_description(self):
        tpl = Template(
            "{% include 'base/check_cell.html' with value=v chk=c %}")
        html = tpl.render(Context({
            'v': True,
            'c': {'severity': 'high', 'description': '"><img src=x>'},
        }))
        self.assertNotIn('<img', html)
        self.assertIn('bg-danger', html)

    def test_recent_scan_helpers(self):
        self.assertEqual(
            _tracker_count("{'detected_trackers': 3, 'total_trackers': 9}"),
            3)
        self.assertIsNone(_tracker_count('not a dict'))
        self.assertIsNone(_tracker_count("{'detected_trackers': 'x'}"))
        self.assertIsNone(_tracker_count(None))

    def test_appsec_summary(self):
        findings = {
            'high': [1, 2], 'warning': [1], 'info': [], 'secure': [1],
            'hotspot': [], 'security_score': 61}
        target = 'mobsf.StaticAnalyzer.views.common.appsec.'
        entry = mock.Mock(MD5='a' * 32)
        with mock.patch(target + 'get_android_dashboard',
                        return_value=findings):
            self.assertEqual(appsec_summary(entry, 'android'), {
                'high': 2, 'warning': 1, 'info': 0, 'secure': 1,
                'hotspot': 0, 'score': 61})
        with mock.patch(target + 'get_ios_dashboard',
                        return_value={'high': []}):
            self.assertIsNone(appsec_summary(entry, 'ios'))
        with mock.patch(target + 'get_ios_dashboard',
                        side_effect=KeyError('code_analysis')):
            self.assertIsNone(appsec_summary(entry, 'ios'))

    def test_source_languages(self):
        android = detect_technologies({'files': [
            'app/src/main/java/com/example/Main.java',
            'app/src/main/kotlin/com/example/Util.kt',
        ], 'app_type': 'studio'}, 'android')
        langs = next(g for g in android if g['label'] == 'Languages')
        self.assertEqual(langs['items'], ['Java', 'Kotlin'])
        ios = detect_technologies({'files': [
            'App/AppDelegate.swift', 'App/Legacy.m',
        ], 'app_type': ''}, 'ios')
        langs = next(g for g in ios if g['label'] == 'Languages')
        self.assertEqual(langs['items'], ['Swift', 'Objective-C'])


class SuppressionRevisionTests(TestCase):

    def test_revision_tracks_suppression_changes(self):
        self.assertEqual(_suppression_revisions({'com.example'}), {})
        rule = SuppressFindings.objects.create(
            PACKAGE_NAME='com.example', SUPPRESS_TYPE='code',
            SUPPRESS_RULE_ID="['rule_a']", SUPPRESS_FILES='{}')
        first = _suppression_revisions({'com.example'})['com.example']
        rule.SUPPRESS_RULE_ID = "['rule_a', 'rule_b']"
        rule.save()
        second = _suppression_revisions({'com.example'})['com.example']
        self.assertNotEqual(first, second)
        rule.delete()
        self.assertEqual(_suppression_revisions({'com.example'}), {})
