# -*- coding: utf_8 -*-
"""Unit tests for JavaScript, TypeScript, Hybrid & Hermes Bytecode analysis."""
import ctypes
import hashlib
import json
import struct
import tempfile
from pathlib import Path

from django.test import TestCase

from hermes_dec.parsers.hbc_file_parser import (
    HBCReader,
    HEADER_MAGIC,
)

from mobsf.StaticAnalyzer.views.common.js_analysis import (
    analyze_js,
    beautify_minified_js,
    is_hermes_bytecode,
    is_minified_js,
    list_js_source_files,
    slice_large_source,
)
from mobsf.StaticAnalyzer.views.common.suppression import (
    process_suppression_js,
)


def _build_hermes_v84_fixture():
    """Construct a minimal valid Hermes v84 bytecode binary for testing."""
    reader = HBCReader()
    header_cls = reader.get_header_reader(84)
    hdr = header_cls()
    reader.header = hdr
    hdr.magic = HEADER_MAGIC
    hdr.version = 84
    hdr.globalCodeIndex = 0
    hdr.functionCount = 1
    hdr.stringKindCount = 1
    hdr.identifierCount = 0

    strings = [
        'global',
        'AsyncStorage',
        'setItem',
        'auth_token',
        'http://api.insecure-hermes.example.com/v1',
        'allowUniversalAccessFromFileURLs',
    ]
    hdr.stringCount = len(strings)
    hdr.overflowStringCount = 0

    str_blob = bytearray()
    small_str_cls = reader.get_small_string_table_entry_reader()
    str_entries = (small_str_cls * len(strings))()
    for i, text in enumerate(strings):
        raw = text.encode('ascii')
        str_entries[i].isUTF16 = 0
        str_entries[i].offset = len(str_blob)
        str_entries[i].length = len(raw)
        str_blob.extend(raw)
    hdr.stringStorageSize = len(str_blob)

    bytecode = (
        bytes([46, 0])
        + bytes([50, 1, 0, 1, 1])
        + bytes([50, 2, 1, 2, 2])
        + struct.pack('<BBH', 109, 3, 3)
        + struct.pack('<BBH', 109, 4, 4)
        + bytes([80, 5, 2, 1, 3, 4])
        + bytes([114, 6])
        + struct.pack('<BBBBH', 55, 0, 6, 1, 5)
        + bytes([90, 7, 4])
        + bytes([88, 7])
    )

    func_hdr_cls = reader.get_small_func_header_reader()
    fn = func_hdr_cls()
    fn.paramCount = 1
    fn.bytecodeSizeInBytes = len(bytecode)
    fn.functionName = 0
    fn.frameSize = 16
    fn.environmentSize = 0

    kind_cls = reader.get_string_kind_entry_reader()
    kind_entry = kind_cls()
    kind_entry.count = len(strings)
    kind_entry.kind = 0

    dbg_hdr_cls = reader.get_debug_info_header_reader()
    dbg_hdr = dbg_hdr_cls()

    def _pad(buf, align=4):
        rem = len(buf) % align
        if rem:
            buf.extend(b'\x00' * (align - rem))

    body = bytearray(bytes(hdr))
    _pad(body, 32)
    fn_pos = len(body)
    body.extend(bytes(fn))
    _pad(body, 4)
    body.extend(bytes(kind_entry))
    _pad(body, 4)
    body.extend(bytes(str_entries))
    _pad(body, 4)
    body.extend(str_blob)
    _pad(body, 4)
    bc_offset = len(body)
    body.extend(bytecode)
    _pad(body, 4)
    dbg_offset = len(body)
    body.extend(bytes(dbg_hdr))

    fn.offset = bc_offset
    fn.infoOffset = dbg_offset
    hdr.debugInfoOffset = dbg_offset
    hdr.fileLength = len(body) + 20

    body[0:ctypes.sizeof(hdr)] = bytes(hdr)
    body[fn_pos:fn_pos + ctypes.sizeof(fn)] = bytes(fn)
    body.extend(hashlib.sha1(body).digest())
    return bytes(body)


class JSAnalysisTests(TestCase):

    def test_hermes_bytecode_decompilation_and_ast_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assets = root / 'assets'
            assets.mkdir()
            bundle = assets / 'index.android.bundle'
            bundle.write_bytes(_build_hermes_v84_fixture())

            is_hbc, ver = is_hermes_bytecode(bundle)
            self.assertTrue(is_hbc)
            self.assertEqual(ver, 84)

            res = analyze_js('0' * 32, root, 'apk')
            self.assertIn('React Native (Hermes)', res['frameworks'])
            self.assertTrue(res['hermes'].get('detected'))
            self.assertEqual(res['hermes'].get('version'), 84)
            self.assertTrue(res['hermes'].get('decompiled'))
            self.assertTrue((assets / 'index.android.bundle.dec.js').is_file())

            findings = res['findings']
            self.assertIn('js_webview_file_access', findings)
            self.assertIn('js_insecure_async_storage', findings)
            self.assertIn('js_dynamic_code_execution', findings)
            self.assertIn('js_cleartext_http_traffic', findings)
            self.assertIn(
                'http://api.insecure-hermes.example.com/v1',
                res['urls_list'])

    def test_react_native_source_and_hybrid_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'package.json').write_text(json.dumps({
                'dependencies': {
                    'react-native': '0.74.0',
                    'expo': '51.0.0',
                    '@capacitor/core': '6.0.0',
                },
            }), encoding='utf-8')

            src_dir = root / 'src'
            src_dir.mkdir()
            (src_dir / 'App.tsx').write_text(
                'import { WebView } from "react-native-webview";\n'
                'import AsyncStorage from '
                '"@react-native-async-storage/async-storage";\n'
                'import { MMKV } from "react-native-mmkv";\n'
                'import { Linking } from "react-native";\n'
                'const API_KEY = "sk_live_9876543210abcdef123456";\n'
                'const store = new MMKV();\n'
                'export function Screen({ deepLink, html }) {\n'
                '  const keyName = "auth_token";\n'
                '  AsyncStorage.setItem(keyName, API_KEY);\n'
                '  Linking.openURL(deepLink);\n'
                '  window.postMessage(API_KEY, "*");\n'
                '  if (__DEV__) { console.log("dev secret:", API_KEY); }\n'
                '  console.log("prod secret_token:", API_KEY);\n'
                '  return (\n'
                '    <WebView\n'
                '      javaScriptEnabled={true}\n'
                '      allowUniversalAccessFromFileURLs={true}\n'
                '      mixedContentMode="always"\n'
                '      originWhitelist={["*"]}\n'
                '      dangerouslySetInnerHTML={{ __html: html }}\n'
                '    />\n'
                '  );\n'
                '}\n',
                encoding='utf-8')

            # node_modules should be ignored
            nm_dir = root / 'node_modules' / 'pkg'
            nm_dir.mkdir(parents=True)
            (nm_dir / 'bad.js').write_text('eval(x);\n', encoding='utf-8')

            # Cordova config.xml & Capacitor config
            (root / 'config.xml').write_text(
                '<widget id="com.example.app">'
                '<access origin="*" />'
                '<allow-navigation href="*" />'
                '</widget>',
                encoding='utf-8')
            (root / 'capacitor.config.json').write_text(json.dumps({
                'appId': 'com.example.app',
                'server': {
                    'cleartext': True,
                    'allowNavigation': ['*.example.com'],
                },
            }), encoding='utf-8')

            res = analyze_js('0' * 32, root, 'zip')
            self.assertIn('React Native', res['frameworks'])
            self.assertIn('Expo', res['frameworks'])
            self.assertIn('Capacitor', res['frameworks'])

            findings = res['findings']
            for expected_rule in (
                'js_webview_javascript_enabled',
                'js_webview_file_access',
                'js_webview_mixed_content',
                'js_webview_origin_wildcard',
                'js_dom_xss_sink',
                'js_postmessage_wildcard_origin',
                'js_insecure_async_storage',
                'js_mmkv_without_encryption',
                'js_hardcoded_secret',
                'js_deeplink_open_url',
                'js_console_sensitive_log',
                'cordova_config_wildcard_access',
                'cordova_config_wildcard_navigation',
                'capacitor_cleartext_traffic',
                'capacitor_wildcard_navigation',
            ):
                self.assertIn(expected_rule, findings, expected_rule)

            # node_modules/pkg/bad.js must not trigger js_dynamic_code_execution
            self.assertNotIn('js_dynamic_code_execution', findings)

            # __DEV__ console.log on line 12 must be excluded; only line 13 matched
            log_lines = findings['js_console_sensitive_log']['files'][
                'src/App.tsx']
            self.assertEqual(log_lines, '13')

    def test_sourcemap_and_embedded_html_in_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            www = root / 'assets' / 'www'
            www.mkdir(parents=True)
            (www / 'index.html').write_text(
                '<html><body><script>\n'
                'document.getElementById("out").innerHTML = location.hash;\n'
                '</script></body></html>\n',
                encoding='utf-8')
            (www / 'app.js.map').write_text(
                '{"version":3,"sources":["src/app.ts"]}',
                encoding='utf-8')

            res = analyze_js('0' * 32, root, 'apk')
            self.assertIn('js_sourcemap_exposed', res['findings'])
            self.assertIn('js_dom_xss_sink', res['findings'])
            self.assertEqual(
                res['findings']['js_dom_xss_sink']['files'][
                    'assets/www/index.html'],
                '2',
            )

            sup = process_suppression_js({
                'frameworks': res['frameworks'],
                'hermes': res['hermes'],
                'findings': res['findings'],
            }, 'com.example.nonexistent')
            self.assertIn('summary', sup)
            self.assertGreaterEqual(sup['summary'].get('warning', 0), 2)

    def test_minified_js_beautification_and_large_source_slice(self):
        minified = (
            'function a(){var x=1;var y=2;return x+y;}' * 30
            + 'function vuln(u){eval(u);}'
        )
        self.assertTrue(is_minified_js(minified))
        formatted = beautify_minified_js(minified)
        self.assertGreater(formatted.count('\n'), 50)
        self.assertIn('eval(u);', formatted)

        big_text = '\n'.join(f'var line_{i} = {i};' for i in range(1, 2001))
        sliced, start_line = slice_large_source(
            big_text, '1000', max_bytes=1000, radius=5)
        self.assertEqual(start_line, 995)
        self.assertIn('var line_1000 = 1000;', sliced)
        self.assertNotIn('var line_10 = 10;', sliced)

    def test_dvrn_vulnerability_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'src'
            src.mkdir()
            (src / 'tokenStorage.ts').write_text(
                'import AsyncStorage from '
                '"@react-native-async-storage/async-storage";\n'
                'export async function saveToken(token: string) {\n'
                '  await AsyncStorage.setItem("authToken", token);\n'
                '}\n',
                encoding='utf-8')
            (src / 'secrets.ts').write_text(
                'export const PREMIUM_API_KEY = "sk_live_dvrn_9f8a2c1b4e7d";\n',
                encoding='utf-8')
            (src / 'PremiumScreen.tsx').write_text(
                'export function PremiumScreen({ isPremium }) {\n'
                '  if (!isPremium) { return null; }\n'
                '  return null;\n'
                '}\n',
                encoding='utf-8')
            (src / 'WebViewScreen.tsx').write_text(
                'export function WebViewScreen() {\n'
                '  const onMessage = (event) => {\n'
                '    const data = JSON.parse(event.nativeEvent.data);\n'
                '  };\n'
                '}\n',
                encoding='utf-8')
            res = analyze_js('0' * 32, root, 'zip')
            findings = res['findings']
            self.assertIn('js_insecure_async_storage', findings)
            self.assertIn('js_hardcoded_secret', findings)
            self.assertIn('js_client_side_auth_gate', findings)
            self.assertIn('js_webview_unverified_onmessage', findings)

    def test_tls_sqlite_injection_and_crypto_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'src'
            src.mkdir()
            (src / 'vuln.js').write_text(
                'cordova.plugin.http.setServerTrustMode("nocheck", a, b);\n'
                'RNFetchBlob.config({ trusty: true }).fetch("GET", u);\n'
                'db.executeSql(`SELECT * FROM users WHERE id=${id}`);\n'
                'tx.executeSql("DELETE FROM notes WHERE id=" + id, []);\n'
                'webview.injectJavaScript(`setUser("${name}")`);\n'
                'ref.executeScript({ code: "go(\'" + url + "\')" });\n'
                'const h = CryptoJS.MD5(password);\n'
                'const c = CryptoJS.DES.encrypt(data, "s3cr3tk3y");\n'
                'const e = CryptoJS.AES.encrypt(d, k, '
                '{ mode: CryptoJS.mode.ECB });\n'
                'const s = crypto.createHash("sha1");\n',
                encoding='utf-8')
            (src / 'safe.js').write_text(
                'db.executeSql("SELECT * FROM users WHERE id=?", [id]);\n'
                'const m = re.exec(prefix + value);\n'
                'webview.injectJavaScript("window.ready = true; true;");\n'
                'const s = crypto.createHash("sha256");\n'
                'const e = CryptoJS.AES.encrypt(data, keyFromKeychain);\n'
                'RNFetchBlob.config({ trusty: false });\n',
                encoding='utf-8')
            findings = analyze_js('0' * 32, root, 'zip')['findings']
            expected = {
                'js_tls_validation_disabled': '1,2',
                'js_sqlite_injection': '3,4',
                'js_webview_script_injection': '5,6',
                'js_weak_crypto': '7,8,9,10',
                'js_crypto_hardcoded_key': '8',
            }
            for rule, lines in expected.items():
                self.assertIn(rule, findings, rule)
                files = findings[rule]['files']
                self.assertEqual(
                    sorted(files['src/vuln.js'].split(',')),
                    sorted(lines.split(',')), rule)
                self.assertNotIn('src/safe.js', files, rule)

    def test_webview_uri_keychain_clipboard_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'src'
            src.mkdir()
            (src / 'vuln.tsx').write_text(
                'const a = <WebView source={{ uri: deepLinkUrl }} />;\n'
                'const b = <WebView source={{ uri: `${host}/pay` }}></WebView>;\n'
                'React.createElement(n.WebView, '
                '{ source: { uri: props.url } });\n'
                'Keychain.setGenericPassword(u, p, '
                '{ accessible: Keychain.ACCESSIBLE.ALWAYS });\n'
                'SecureStore.setItemAsync("k", v, '
                '{ keychainAccessible: SecureStore.ALWAYS });\n'
                'Clipboard.setString(user.password);\n'
                'navigator.clipboard.writeText(authToken);\n'
                'const c = <WebView allowingReadAccessToURL={docsDir} />;\n'
                'setTimeout("refresh(" + id + ")", 100);\n'
                'window.setInterval("poll()", 500);\n',
                encoding='utf-8')
            (src / 'safe.tsx').write_text(
                'const a = <Image source={{ uri: avatarUrl }} />;\n'
                'const b = <WebView source={{ uri: "https://example.com" }} />;\n'
                'Keychain.setGenericPassword(u, p, { accessible: '
                'Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY });\n'
                'Clipboard.setString(orderId);\n'
                'setTimeout(() => refresh(id), 100);\n'
                'setTimeout(cb || noop, 100);\n',
                encoding='utf-8')
            findings = analyze_js('0' * 32, root, 'zip')['findings']
            expected = {
                'js_webview_dynamic_uri': '1,2,3',
                'js_keychain_weak_accessibility': '4,5',
                'js_clipboard_sensitive_data': '6,7',
                'js_webview_file_access': '8',
                'js_dynamic_code_execution': '9,10',
            }
            for rule, lines in expected.items():
                self.assertIn(rule, findings, rule)
                files = findings[rule]['files']
                self.assertEqual(
                    sorted(files['src/vuln.tsx'].split(',')),
                    sorted(lines.split(',')), rule)
                self.assertNotIn('src/safe.tsx', files, rule)

    def test_js_source_listing_prunes_and_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            www = root / 'assets' / 'www'
            (www / 'plugins' / 'cordova-plugin-x').mkdir(parents=True)
            (www / 'app.js').write_text('var a = 1;\n', encoding='utf-8')
            (www / 'plugins' / 'cordova-plugin-x' / 'x.js').write_text(
                'eval(x);\n', encoding='utf-8')
            for skipped in ('java_source', 'smali_source', 'plugins'):
                sdir = root / skipped
                sdir.mkdir()
                (sdir / 'skip.js').write_text('eval(y);\n', encoding='utf-8')

            expected = [
                'assets/www/app.js',
                'assets/www/plugins/cordova-plugin-x/x.js',
            ]
            self.assertEqual(list_js_source_files(root), expected)

            res = analyze_js('0' * 32, root, 'apk')
            self.assertEqual(res['source_files'], expected)
            self.assertIn('js_dynamic_code_execution', res['findings'])

            cached = expected + ['../../etc/passwd', 'assets/missing.js', 1]
            self.assertEqual(list_js_source_files(root, cached), expected)
