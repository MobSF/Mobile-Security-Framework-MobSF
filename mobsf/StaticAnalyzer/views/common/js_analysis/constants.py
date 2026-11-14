# -*- coding: utf_8 -*-
"""JavaScript analysis constants and limits."""


HERMES_MAGIC = b'\xc6\x1f\xbc\x03\xc1\x03\x19\x1f'
MAX_JS_FILE_BYTES = 50 * 1024 * 1024
MAX_URL_SCAN_BYTES = 25 * 1024 * 1024
JS_SOURCE_EXTS = {
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.vue', '.svelte', '.html', '.htm',
}
BUNDLE_EXTS = {'.bundle', '.jsbundle', '.hbc'}
SKIP_JS_DIRS = {
    'node_modules', '.git', '.gradle', 'build', 'dist', '.expo',
    '.next', 'coverage', 'pods', 'carthage', 'deriveddata',
    'java_source', 'smali_source', 'apktool_out', '__macosx',
    'vendor', 'frameworks', 'plugins', '_codesignature', 'sc_info',
}
# Cordova/Capacitor ship plugin JS under www/plugins or public/plugins.
WEB_ROOT_DIRS = {'www', 'public'}
EXPO_CONFIG_FILES = {'app.config', 'app.manifest', 'app.json'}
HYBRID_CONFIG_FILES = {'config.xml', 'capacitor.config.json'} | (
    EXPO_CONFIG_FILES)
EXPO_DEV_CLIENT_FILES = {
    'expo_dev_launcher_android.bundle', 'exdevmenuapp.android.js'}
EXPO_DEV_CLIENT_DIRS = {'exdevlauncher.bundle', 'exdevmenu.bundle'}
MAX_CONFIG_BYTES = 5 * 1024 * 1024
MAX_LISTED_JS_FILES = 10000
SKIP_VENDOR_FILES = {
    'cordova.js', 'cordova_plugins.js', 'phonegap.js',
    'jquery.js', 'jquery.min.js', 'bootstrap.js', 'bootstrap.min.js',
    'polyfills.js', 'runtime.js',
}
BEAUTIFY_EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.bundle', '.jsbundle'}
CHUNK_LINES = 50000
MAX_CHUNK_THRESHOLD_BYTES = 3 * 1024 * 1024
MAX_SAST_JS_BYTES = 256 * 1024 * 1024
SAST_BATCH_BYTES = 32 * 1024 * 1024
