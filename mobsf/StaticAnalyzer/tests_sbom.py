# -*- coding: utf_8 -*-
"""Unit tests for Android and iOS offline SBOM extraction."""
import json
import plistlib
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android.sbom_analysis import sbom as android_sbom
from mobsf.StaticAnalyzer.views.common.sbom import (
    extract_android_sbom,
    extract_ios_sbom,
    ios_sbom,
)


class SBOMExtractionTests(SimpleTestCase):

    def test_android_sbom_extraction_and_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Valid META-INF/*.version (including kotlinx_ multi-underscore)
            meta_inf = root / 'META-INF'
            meta_inf.mkdir()
            (meta_inf / 'androidx.activity_activity-ktx.version').write_text(
                '1.8.0\n', encoding='utf-8')
            (meta_inf / 'kotlinx_coroutines_android.version').write_text(
                '1.7.3\n', encoding='utf-8')
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

            # 5. Multiline libs.versions.toml, build.gradle.kts, gradle.lockfile,
            # pubspec.lock, and nested v1 package-lock.json
            gradle_dir = root / 'gradle'
            gradle_dir.mkdir()
            (gradle_dir / 'libs.versions.toml').write_text(
                '[versions]\nretrofit = "2.9.0"\n\n'
                '[libraries]\nretrofit = { module = '
                '"com.squareup.retrofit2:retrofit", version.ref = "retrofit" }\n'
                'okhttp = "com.squareup.okhttp3:okhttp:4.12.0"\n',
                encoding='utf-8')
            (root / 'build.gradle.kts').write_text(
                'dependencies {\n'
                '    implementation("javax.inject:javax.inject:1")\n'
                '    implementation("com.example:dynamic-range:1.+")\n'
                '}\n',
                encoding='utf-8')
            (root / 'gradle.lockfile').write_text(
                'com.google.code.gson:gson:2.8.6=compileClasspath\n',
                encoding='utf-8')
            (root / 'pubspec.lock').write_text(
                'packages:\n  http:\n    dependency: "direct main"\n'
                '    version: "0.13.3"\n',
                encoding='utf-8')
            (root / 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 2,
                'dependencies': {
                    'react-native': {
                        'version': '0.73.0',
                        'dependencies': {
                            'hermes-engine': {'version': '0.11.0'},
                        },
                    },
                },
                'packages': {
                    'node_modules/string-width-cjs': {
                        'name': 'string-width',
                        'version': '4.2.3',
                    },
                    'packages/mobile/node_modules/ metro': {
                        'name': 'metro',
                        'version': '0.80.0',
                    },
                },
            }), encoding='utf-8')

            versioned = extract_android_sbom(root)
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
            self.assertIn('com.squareup.okhttp3:okhttp@4.12.0', versioned)
            self.assertIn('javax.inject:javax.inject@1', versioned)
            self.assertNotIn('com.example:dynamic-range@1.+', versioned)
            self.assertIn('com.google.code.gson:gson@2.8.6', versioned)
            self.assertIn('http@0.13.3', versioned)
            self.assertIn('react-native@0.73.0', versioned)
            self.assertIn('hermes-engine@0.11.0', versioned)
            self.assertIn('string-width@4.2.3', versioned)
            self.assertIn('metro@0.80.0', versioned)
            # Corrupted lproj entry must not be present
            self.assertFalse(
                any('0d2e225546bdb069e583c5af4d824d75' in v for v in versioned))

    def test_ios_sbom_extraction_deduplicates_nested_bundles(self):
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

            # Package.resolved, Cartfile.resolved, and Podfile.lock in source dir
            (root / 'Package.resolved').write_text(json.dumps({
                'pins': [
                    {
                        'identity': 'vapor',
                        'location': 'https://github.com/vapor/vapor.git',
                        'state': {'version': '4.50.0'},
                    },
                    {'state': 'invalid'},
                ],
            }), encoding='utf-8')
            (root / 'Cartfile.resolved').write_text(
                'git "https://github.com/SnapKit/SnapKit.git" "5.7.1"\n',
                encoding='utf-8')
            (root / 'Podfile.lock').write_text(
                'PODS:\n  - SDWebImage/Core (5.21.7)\n'
                '  - Socket.IO-Client-Swift/Core (16.1.0)\n'
                'DEPENDENCIES:\n  - SDWebImage\n',
                encoding='utf-8')

            versioned = extract_ios_sbom(
                {'app_root': root.as_posix(), 'app_dir': tmp})
            self.assertIn('Alamofire@5.12.0', versioned)
            self.assertIn('vapor@4.50.0', versioned)
            self.assertIn('SnapKit/SnapKit@5.7.1', versioned)
            self.assertIn('SDWebImage@5.21.7', versioned)
            self.assertIn('Socket.IO-Client-Swift@16.1.0', versioned)
            self.assertFalse(any(v.startswith('Flutter@') for v in versioned))

    def test_android_and_ios_sbom_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            res_a = android_sbom(
                Path(tmp),
                [('com/example/Foo.java', 'package com.example;\nclass Foo {}')])
            self.assertIn('sbom_versioned', res_a)
            self.assertIn('sbom_packages', res_a)
            self.assertEqual(res_a['sbom_packages'], ['com.example'])

            res_i = ios_sbom({'app_dir': tmp})
            self.assertIn('sbom_versioned', res_i)
            self.assertIn('sbom_packages', res_i)
