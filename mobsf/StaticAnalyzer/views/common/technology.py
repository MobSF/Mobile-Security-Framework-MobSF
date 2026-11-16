# -*- coding: utf_8 -*-
"""Technology fingerprints from data already collected during a scan."""

ANDROID_ABIS = (
    'arm64-v8a', 'armeabi-v7a', 'armeabi',
    'x86_64', 'x86', 'riscv64', 'mips64', 'mips',
)
APKID_PROTECTIONS = ('packer', 'protector', 'obfuscator')
# Shared library basename -> (framework, language)
ANDROID_NATIVE_FRAMEWORKS = (
    ('libflutter.so', 'Flutter', 'Dart'),
    ('libmonodroid.so', 'Xamarin / .NET', 'C#'),
    ('libunity.so', 'Unity', 'C#'),
    ('libil2cpp.so', 'Unity IL2CPP', None),
    ('libue4.so', 'Unreal Engine', None),
    ('libunreal.so', 'Unreal Engine', None),
    ('libgodot_android.so', 'Godot', None),
    ('libnativescript.so', 'NativeScript', 'JavaScript'),
    ('libpybundle.so', 'Python (Kivy)', 'Python'),
)
# Shared library basename prefix -> (framework, language)
ANDROID_NATIVE_PREFIXES = (
    ('libcocos', 'Cocos2d-x', None),
    ('libqt5core', 'Qt', None),
    ('libqt6core', 'Qt', None),
    ('libpython3', 'Python', 'Python'),
)
REACT_NATIVE_LIBS = (
    'libreactnativejni.so',
    'libreact_nativemodule_core.so',
    'libfabricjni.so',
)
# Path fragment -> (framework, language)
IOS_PATH_FRAMEWORKS = (
    ('flutter.framework/', 'Flutter', 'Dart'),
    ('unityframework.framework/', 'Unity', 'C#'),
    ('hermes.framework/', 'React Native (Hermes)', 'JavaScript'),
    ('main.jsbundle', 'React Native', 'JavaScript'),
    ('www/cordova.js', 'Cordova', 'JavaScript'),
    ('xamarin.ios.dll', 'Xamarin / .NET', 'C#'),
    ('microsoft.ios.dll', 'Xamarin / .NET', 'C#'),
    ('nativescript.framework/', 'NativeScript', 'JavaScript'),
)


def _add(items, value):
    if value and value not in items:
        items.append(value)


def _paths(files):
    out = []
    for item in files or []:
        if isinstance(item, str):
            out.append(item.replace('\\', '/').lower())
    return out


def _js_frameworks(js_analysis):
    if isinstance(js_analysis, dict):
        fws = js_analysis.get('frameworks') or []
        return [f for f in fws if isinstance(f, str)]
    return []


def _apkid_labels(apkid, kinds):
    labels = []
    if not isinstance(apkid, dict):
        return labels
    for detections in apkid.values():
        if not isinstance(detections, dict):
            continue
        for kind in kinds:
            for label in detections.get(kind) or []:
                if (isinstance(label, str)
                        and not label.lower().startswith('unknown')):
                    _add(labels, label)
    return labels


def _android(ctx):
    paths = _paths(ctx.get('files'))
    names = {p.rsplit('/', 1)[-1] for p in paths}
    langs, fws, abis, build, warnings = [], [], [], [], []
    js = _js_frameworks(ctx.get('js_analysis'))

    if any(p.endswith('.dex') for p in paths) or ctx.get('app_type') in (
            'jar', 'aar'):
        _add(langs, 'Java')
    if any(p.endswith(('.kotlin_builtins', '.kotlin_module'))
           for p in paths):
        _add(langs, 'Kotlin')
    native = [p for p in paths if p.startswith('lib/') and p.endswith('.so')]
    for path in native:
        parts = path.split('/')
        if len(parts) >= 3 and parts[1] in ANDROID_ABIS:
            _add(abis, parts[1])
    for lib, framework, lang in ANDROID_NATIVE_FRAMEWORKS:
        if lib in names:
            _add(fws, framework)
            _add(langs, lang)
    for prefix, framework, lang in ANDROID_NATIVE_PREFIXES:
        if any(n.startswith(prefix) and n.endswith('.so') for n in names):
            _add(fws, framework)
            _add(langs, lang)
    if (any(lib in names for lib in REACT_NATIVE_LIBS)
            or 'assets/index.android.bundle' in paths):
        _add(fws, 'React Native')
    if 'libhermes.so' in names:
        _add(fws, 'Hermes')
    if 'assets/www/cordova.js' in paths:
        _add(fws, 'Cordova')
    for framework in js:
        if framework == 'React Native (Hermes)':
            _add(fws, 'React Native')
            _add(fws, 'Hermes')
        else:
            _add(fws, framework)
    if js or 'React Native' in fws or 'Cordova' in fws:
        _add(langs, 'JavaScript')
    if any(p.startswith('meta-inf/androidx.compose.') for p in paths):
        _add(fws, 'Jetpack Compose')
    if any(p.startswith('meta-inf/') and 'firebase' in p for p in paths):
        _add(fws, 'Firebase')
    if native:
        _add(langs, 'C/C++')

    for label in _apkid_labels(ctx.get('apkid'), ('compiler',)):
        _add(build, label)
    protections = _apkid_labels(ctx.get('apkid'), APKID_PROTECTIONS)
    if any(n.startswith('libfrida-gadget') for n in names):
        _add(warnings, 'Frida Gadget')
    return langs, fws, abis, build, protections, warnings


def _ios(ctx):
    paths = _paths(ctx.get('files'))
    langs, fws, build, warnings = [], [], [], []
    app_type = str(ctx.get('app_type') or '')
    if 'Swift' in app_type:
        _add(langs, 'Swift')
    if 'Objective' in app_type:
        _add(langs, 'Objective-C')
    for fragment, framework, lang in IOS_PATH_FRAMEWORKS:
        if any(fragment in p for p in paths):
            _add(fws, framework)
            _add(langs, lang)
    for framework in _js_frameworks(ctx.get('js_analysis')):
        _add(fws, framework)
        _add(langs, 'JavaScript')
    if any(p.endswith('googleservice-info.plist')
           or 'firebasecore.framework/' in p for p in paths):
        _add(fws, 'Firebase')
    embedded = {
        p.split('.framework/', 1)[0].rsplit('/', 1)[-1]
        for p in paths if '/frameworks/' in p and '.framework/' in p}
    if embedded:
        build.append(f'{len(embedded)} embedded frameworks')
    if any('fridagadget' in p for p in paths):
        _add(warnings, 'Frida Gadget')
    return langs, fws, [], build, [], warnings


def detect_technologies(ctx, platform):
    """Return technology groups for the report header."""
    langs, fws, abis, build, protections, warnings = (
        _ios(ctx) if platform == 'ios' else _android(ctx))
    groups = [
        ('Languages', 'fas fa-code', langs, ''),
        ('Frameworks', 'fas fa-layer-group', fws, ''),
        ('Native ABIs', 'fas fa-microchip', abis, ''),
        ('Build', 'fas fa-hammer', build, ''),
        ('Protection', 'fas fa-shield-alt', protections, ''),
        ('Instrumentation', 'fas fa-exclamation-triangle', warnings,
         'tech-warn'),
    ]
    return [
        {'label': label, 'icon': icon, 'items': items, 'css': css}
        for label, icon, items, css in groups if items]
