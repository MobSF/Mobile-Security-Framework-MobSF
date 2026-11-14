# -*- coding: utf_8 -*-
"""Hybrid and React Native framework detection."""
import json

from mobsf.StaticAnalyzer.views.common.js_analysis.files import (
    is_valid_candidate,
)


def detect_frameworks_from_package_json(scan_root, frameworks):
    """Inspect root package.json for JS/mobile framework dependencies."""
    pkg_json = scan_root / 'package.json'
    if not is_valid_candidate(scan_root, pkg_json):
        return
    try:
        data = json.loads(pkg_json.read_text('utf-8', 'ignore'))
    except Exception:
        return
    if not isinstance(data, dict):
        return
    deps = set()
    for section in ('dependencies', 'devDependencies'):
        sec = data.get(section)
        if isinstance(sec, dict):
            deps.update(sec.keys())
    if 'react-native' in deps:
        frameworks.add('React Native')
    if 'expo' in deps:
        frameworks.add('Expo')
    if '@capacitor/core' in deps or '@capacitor/android' in deps:
        frameworks.add('Capacitor')
    if any(d.startswith(('cordova-', '@ionic/')) for d in deps):
        frameworks.add('Cordova / Ionic')
    if '@nativescript/core' in deps or 'tns-core-modules' in deps:
        frameworks.add('NativeScript')


def classify_path_framework(rel_posix, frameworks):
    """Infer hybrid framework from relative asset paths."""
    low = rel_posix.lower()
    if low.endswith(('index.android.bundle', 'main.jsbundle', 'index.ios.bundle')):
        frameworks.add('React Native')
    elif '/www/' in f'/{low}' and (low.endswith('.html') or 'cordova' in low):
        frameworks.add('Cordova / Ionic')
    elif 'capacitor.config.json' in low or '/public/index.html' in f'/{low}':
        frameworks.add('Capacitor')
    elif '/app/bundle.js' in f'/{low}' or '/app/vendor.js' in f'/{low}':
        frameworks.add('NativeScript')
    elif low.endswith(('app.manifest', 'exshell.plist', 'expo.plist')):
        frameworks.add('Expo')
