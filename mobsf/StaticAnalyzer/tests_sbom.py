# -*- coding: utf_8 -*-
"""Unit tests for Android and iOS SBOM extraction and OSV scanning."""
import json
import plistlib
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android.sbom_analysis import sbom as android_sbom
from mobsf.StaticAnalyzer.views.common.appsec import common_fields
from mobsf.StaticAnalyzer.views.common.sbom import (
    check_osv_vulnerabilities,
    extract_android_components,
    extract_ios_components,
    ios_sbom,
)


class SBOMAndOSVTests(SimpleTestCase):

    def test_android_component_extraction_and_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Valid META-INF/*.version (including kotlinx_ multi-underscore)
            meta_inf = root / 'META-INF'
            meta_inf.mkdir()
            (meta_inf / 'androidx.activity_activity-ktx.version').write_text(
                '1.8.0\n', encoding='utf-8')
            (meta_inf / 'kotlinx_coroutines_android.version').write_text(
                '1.7.3\n', encoding='utf-8')
            # Dynamic task version should stay in sbom_versioned but not OSV
            (meta_inf / 'androidx.lifecycle_lifecycle-runtime.version').write_text(
                "task ':lifecycle:writeVersionFile' property 'version'\n",
                encoding='utf-8')

            # 2. Non-META-INF binary .version file must be ignored
            lproj = root / 'Base.lproj'
            lproj.mkdir()
            (lproj / '0d2e225546bdb069e583c5af4d824d75.version').write_bytes(
                b'\x00')

            # 3. Google Play / Firebase client .properties and pom.properties
            (root / 'play-services-auth.properties').write_text(
                'version=21.5.0\nclient=play-services-auth\n',
                encoding='utf-8')
            (root / 'integrity.properties').write_text(
                'version=1.4.0\nclient=integrity\n',
                encoding='utf-8')
            (root / 'billing.properties').write_text(
                'version=7.0.0\nclient=billing\n',
                encoding='utf-8')
            (root / 'firebase-messaging.properties').write_text(
                'version=24.0.0\nclient=firebase-messaging\n',
                encoding='utf-8')
            pom_dir = meta_inf / 'maven' / 'com.squareup.okio' / 'okio'
            pom_dir.mkdir(parents=True)
            (pom_dir / 'pom.properties').write_text(
                'groupId=com.squareup.okio\nartifactId=okio\nversion=3.4.0\n',
                encoding='utf-8')

            # 4. META-INF/DEPENDENCIES
            (meta_inf / 'DEPENDENCIES').write_text(
                '  - Apache Commons (http://apache.org) '
                'commons-logging:commons-logging:jar:1.2\n',
                encoding='utf-8')

            # 5. Multiline libs.versions.toml, gradle.lockfile, pubspec.lock
            gradle_dir = root / 'gradle'
            gradle_dir.mkdir()
            (gradle_dir / 'libs.versions.toml').write_text(
                '[versions]\nretrofit = "2.9.0"\n\n'
                '[libraries]\nretrofit = { module = '
                '"com.squareup.retrofit2:retrofit", version.ref = "retrofit" }\n',
                encoding='utf-8')
            (root / 'gradle.lockfile').write_text(
                'com.google.code.gson:gson:2.8.6=compileClasspath\n',
                encoding='utf-8')
            (root / 'pubspec.lock').write_text(
                'packages:\n  http:\n    dependency: "direct main"\n'
                '    version: "0.13.3"\n',
                encoding='utf-8')

            versioned, components = extract_android_components(root)
            self.assertIn(
                'androidx.activity:activity-ktx@1.8.0', versioned)
            self.assertIn(
                'org.jetbrains.kotlinx:kotlinx-coroutines-android@1.7.3',
                versioned)
            self.assertIn(
                'androidx.lifecycle:lifecycle-runtime@dynamic', versioned)
            self.assertIn(
                'com.google.android.gms:play-services-auth@21.5.0', versioned)
            self.assertIn(
                'com.google.android.play:integrity@1.4.0', versioned)
            self.assertIn(
                'com.android.billingclient:billing@7.0.0', versioned)
            self.assertIn(
                'com.google.firebase:firebase-messaging@24.0.0', versioned)
            self.assertIn('com.squareup.okio:okio@3.4.0', versioned)
            self.assertIn(
                'commons-logging:commons-logging@1.2', versioned)
            self.assertIn(
                'com.squareup.retrofit2:retrofit@2.9.0', versioned)
            self.assertIn('com.google.code.gson:gson@2.8.6', versioned)
            self.assertIn('http@0.13.3', versioned)
            # Corrupted lproj entry must not be present
            self.assertFalse(
                any('0d2e225546bdb069e583c5af4d824d75' in v for v in versioned))
            # Dynamic entries must not be sent to OSV
            self.assertFalse(
                any(c['version'] == 'dynamic' for c in components))

    def test_ios_component_extraction_deduplicates_nested_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'Payload' / 'Test.app'
            fw_dir = root / 'Frameworks' / 'Alamofire.framework'
            fw_dir.mkdir(parents=True)
            with open(fw_dir / 'Info.plist', 'wb') as fp:
                plistlib.dump({
                    'CFBundleIdentifier': 'org.cocoapods.Alamofire',
                    'CFBundleExecutable': 'Alamofire',
                    'CFBundleShortVersionString': '5.12.0',
                }, fp)
            # Nested privacy bundle inside framework should be skipped
            bundle_dir = fw_dir / 'Alamofire.bundle'
            bundle_dir.mkdir()
            with open(bundle_dir / 'Info.plist', 'wb') as fp:
                plistlib.dump({
                    'CFBundleIdentifier': 'org.cocoapods.Alamofire',
                    'CFBundleName': 'Alamofire',
                    'CFBundleShortVersionString': '5.12.0',
                }, fp)
            # Flutter engine stub should be skipped
            fl_dir = root / 'Frameworks' / 'Flutter.framework'
            fl_dir.mkdir()
            with open(fl_dir / 'Info.plist', 'wb') as fp:
                plistlib.dump({
                    'CFBundleIdentifier': 'io.flutter.flutter',
                    'CFBundleExecutable': 'Flutter',
                    'CFBundleShortVersionString': '1.0',
                }, fp)

            # Package.resolved in source dir
            (root / 'Package.resolved').write_text(json.dumps({
                'pins': [{
                    'identity': 'vapor',
                    'location': 'https://github.com/vapor/vapor.git',
                    'state': {'version': '4.50.0'},
                }],
            }), encoding='utf-8')

            with mock.patch(
                'mobsf.StaticAnalyzer.views.common.sbom.'
                '_resolve_pod_github_repo',
                side_effect=lambda name, online=True: (
                    'Alamofire/Alamofire' if name == 'Alamofire' else None),
            ):
                versioned, components = extract_ios_components(
                    {'app_root': root.as_posix(), 'app_dir': tmp})
            self.assertIn('Alamofire@5.12.0', versioned)
            self.assertIn('vapor@4.50.0', versioned)
            self.assertFalse(any(v.startswith('Flutter@') for v in versioned))
            swift_names = {
                c['name'] for c in components if c['ecosystem'] == 'SwiftURL'
            }
            self.assertIn('github.com/Alamofire/Alamofire', swift_names)
            self.assertIn('github.com/vapor/vapor', swift_names)

    def test_osv_batch_vulnerability_matching_and_appsec(self):
        components = [
            {
                'ecosystem': 'Maven',
                'name': 'com.google.code.gson:gson',
                'version': '2.8.6',
                'display': 'com.google.code.gson:gson',
            },
        ]
        batch_resp = mock.MagicMock(status_code=200)
        batch_resp.json.return_value = {
            'results': [{'vulns': [{'id': 'GHSA-4jrv-ppp4-jm57'}]}],
        }
        detail_resp = mock.MagicMock(status_code=200)
        detail_resp.json.return_value = {
            'id': 'GHSA-4jrv-ppp4-jm57',
            'aliases': ['CVE-2022-25647'],
            'summary': 'Deserialization of Untrusted Data in Gson',
            'database_specific': {'severity': 'HIGH'},
            'affected': [{
                'ranges': [{
                    'events': [{'introduced': '0'}, {'fixed': '2.8.9'}],
                }],
            }],
        }

        with mock.patch(
            'mobsf.StaticAnalyzer.views.common.sbom.is_internet_available',
            return_value=True,
        ), mock.patch(
            'mobsf.StaticAnalyzer.views.common.sbom.requests.post',
            return_value=batch_resp,
        ), mock.patch(
            'mobsf.StaticAnalyzer.views.common.sbom.requests.get',
            return_value=detail_resp,
        ):
            vulns = check_osv_vulnerabilities(components)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['id'], 'GHSA-4jrv-ppp4-jm57')
        self.assertEqual(vulns[0]['aliases'], ['CVE-2022-25647'])
        self.assertEqual(vulns[0]['severity'], 'high')
        self.assertEqual(vulns[0]['fixed'], '2.8.9')

        findings = {
            'high': [], 'warning': [], 'info': [],
            'secure': [], 'hotspot': [],
        }
        data = {
            'md5': 'a' * 32,
            'version_name': '1.0',
            'code_analysis': {'findings': {}},
            'permissions': {},
            'file_analysis': [],
            'domains': {},
            'firebase_urls': [],
            'trackers': {},
            'secrets': [],
            'sbom': {'sbom_vulnerabilities': vulns},
        }
        common_fields(findings, data)
        self.assertEqual(len(findings['high']), 1)
        self.assertIn(
            'com.google.code.gson:gson@2.8.6',
            findings['high'][0]['title'])
        self.assertIn('CVE-2022-25647', findings['high'][0]['description'])

    def test_android_and_ios_sbom_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            'mobsf.StaticAnalyzer.views.common.sbom.is_internet_available',
            return_value=False,
        ):
            res_a = android_sbom(
                Path(tmp),
                [('com/example/Foo.java', 'package com.example;\nclass Foo {}')])
            self.assertIn('sbom_versioned', res_a)
            self.assertIn('sbom_packages', res_a)
            self.assertIn('sbom_vulnerabilities', res_a)
            self.assertEqual(res_a['sbom_packages'], ['com.example'])

            res_i = ios_sbom({'app_dir': tmp})
            self.assertIn('sbom_versioned', res_i)
            self.assertIn('sbom_vulnerabilities', res_i)
