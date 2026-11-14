# -*- coding: utf_8 -*-
"""Unit tests for APPX/MSIX static analysis."""
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from asn1crypto import cms

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from django.conf import settings
from django.test import SimpleTestCase, TestCase

from mobsf.StaticAnalyzer.views.windows import windows
from mobsf.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_analysis,
)
from mobsf.StaticAnalyzer.views.windows.manifest import (
    P7X_MAGIC,
    analyze_signature,
    parse_manifest,
)
from mobsf.StaticAnalyzer.views.windows.pe import NA, PEChecksec
from mobsf.StaticAnalyzer.views.windows.strings import extract_strings

SAMPLE = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'test_files' / (
    'windows.appx')
PUBLISHER = 'CN=Contoso, O=Contoso Ltd, S=Washington, C=US'

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:desktop6="http://schemas.microsoft.com/appx/manifest/desktop/windows10/6"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Contoso.App" Publisher="{publisher}"
    Version="1.2.3.0" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Contoso App</DisplayName>
    <PublisherDisplayName>Contoso</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0"
      MaxVersionTested="10.0.22621.0"/>
    <PackageDependency Name="Microsoft.VCLibs.140.00.Debug"
      MinVersion="14.0.0.0" Publisher="CN=Microsoft Corporation"/>
  </Dependencies>
  <Applications>
    <Application Id="App" Executable="bin\\App.exe"
      EntryPoint="Windows.FullTrustApplication">
      <uap:ApplicationContentUriRules>
        <uap:Rule Type="include" Match="http://contoso.example/"
          WindowsRuntimeAccess="all"/>
      </uap:ApplicationContentUriRules>
      <Extensions>
        <uap:Extension Category="windows.protocol">
          <uap:Protocol Name="contoso"/>
        </uap:Extension>
        <desktop6:Extension Category="windows.service"
          Executable="svc.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="ContosoSvc" StartupType="auto"
            StartAccount="localSystem"/>
        </desktop6:Extension>
      </Extensions>
    </Application>
  </Applications>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
    <DeviceCapability Name="webcam"/>
  </Capabilities>
</Package>
"""


def _rules(findings):
    return {f['rule']: f for f in findings}


def _make_cert(subject, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_after = now - timedelta(days=1) if expired else now + timedelta(
        days=30)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=60))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256()))
    return cert, key


def _write_p7x(root, subject, expired=False, digest=None):
    cert, key = _make_cert(subject, expired)
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b'AppxBlockMap')
        .add_signer(cert, key, digest or hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    (Path(root) / 'AppxSignature.p7x').write_bytes(P7X_MAGIC + der)


def _contoso_name():
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Contoso'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Contoso Ltd'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Washington'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    ])


class ManifestTests(SimpleTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _parse(self, text):
        path = self.tmp / 'AppxManifest.xml'
        path.write_text(text, encoding='utf-8')
        return parse_manifest(path)

    def test_identity_and_findings(self):
        info = self._parse(MANIFEST.format(publisher=PUBLISHER))
        self.assertEqual(info['package_name'], 'Contoso.App')
        self.assertEqual(info['version'], '1.2.3.0')
        self.assertEqual(info['arch'], 'x64')
        self.assertEqual(info['app_name'], 'Contoso App')
        self.assertEqual(info['min_os_version'], '10.0.17763.0')
        self.assertEqual(info['executables'], ['bin\\App.exe'])
        rules = _rules(info['findings'])
        self.assertEqual(rules['full_trust_application']['severity'], 'high')
        self.assertEqual(rules['content_uri_cleartext']['severity'], 'high')
        self.assertIn('content_uri_winrt_access', rules)
        self.assertIn('windows_protocol', rules)
        self.assertIn('contoso', rules['windows_protocol']['title'])
        self.assertEqual(rules['windows_service']['severity'], 'high')
        self.assertIn('LocalSystem', rules['windows_service']['description'])
        self.assertIn('debug_dependency', rules)

    def test_capabilities(self):
        info = self._parse(MANIFEST.format(publisher=PUBLISHER))
        caps = {c['name']: c for c in info['capabilities']}
        self.assertEqual(caps['runFullTrust']['type'], 'Restricted')
        self.assertEqual(caps['runFullTrust']['severity'], 'high')
        self.assertEqual(caps['internetClient']['type'], 'General')
        self.assertEqual(caps['webcam']['type'], 'Device')

    def test_xxe_rejected(self):
        external = self.tmp / 'external.txt'
        external.write_text('external entity content')
        xxe = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE p [<!ENTITY x SYSTEM "file://{external}">]>'
            '<Package><Properties><DisplayName>&x;</DisplayName>'
            '</Properties></Package>')
        info = self._parse(xxe)
        self.assertEqual(info['app_name'], '')
        self.assertEqual(info['findings'], [])

    def test_malformed_and_missing(self):
        self.assertEqual(self._parse('<Package><oops')['package_name'], '')
        self.assertEqual(
            parse_manifest(self.tmp / 'missing.xml')['findings'], [])

    def test_symlinked_manifest_ignored(self):
        target = self.tmp / 'real.xml'
        target.write_text(MANIFEST.format(publisher=PUBLISHER))
        link = self.tmp / 'AppxManifest.xml'
        link.symlink_to(target)
        self.assertEqual(parse_manifest(link)['package_name'], '')


class SignatureTests(SimpleTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unsigned(self):
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertFalse(result['signed'])
        self.assertIn('package_unsigned', _rules(result['findings']))

    def test_invalid_signature(self):
        (self.tmp / 'AppxSignature.p7x').write_bytes(P7X_MAGIC + b'junk')
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertFalse(result['signed'])
        self.assertIn('package_signature_invalid', _rules(result['findings']))

    def test_matching_publisher(self):
        _write_p7x(self.tmp, _contoso_name())
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertTrue(result['signed'])
        self.assertEqual(result['hash_algorithm'], 'sha256')
        rules = _rules(result['findings'])
        self.assertNotIn('package_publisher_mismatch', rules)
        self.assertIn('package_self_signed', rules)

    def test_certificate_only_is_not_signed(self):
        cert, _ = _make_cert(_contoso_name())
        der = pkcs7.serialize_certificates(
            [cert], serialization.Encoding.DER)
        (self.tmp / 'AppxSignature.p7x').write_bytes(P7X_MAGIC + der)
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertFalse(result['signed'])
        self.assertIn('package_signature_invalid', _rules(result['findings']))

    def test_signer_digest_used_for_hash_algorithm(self):
        _write_p7x(self.tmp, _contoso_name(), digest=hashes.SHA512())
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertEqual(result['hash_algorithm'], 'sha512')

    def test_weak_signer_digest(self):
        _write_p7x(self.tmp, _contoso_name())
        sig = self.tmp / 'AppxSignature.p7x'
        info = cms.ContentInfo.load(sig.read_bytes()[len(P7X_MAGIC):])
        info['content']['signer_infos'][0]['digest_algorithm'] = {
            'algorithm': 'sha1'}
        sig.write_bytes(P7X_MAGIC + info.dump(force=True))
        result = analyze_signature(self.tmp, PUBLISHER)
        self.assertEqual(result['hash_algorithm'], 'sha1')
        self.assertIn('package_weak_signature', _rules(result['findings']))

    def test_publisher_with_escaped_comma(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Contoso, Inc.'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        ])
        _write_p7x(self.tmp, name)
        for publisher in ('CN="Contoso, Inc.", C=US',
                          'CN=Contoso\\, Inc., C=US'):
            rules = _rules(analyze_signature(self.tmp, publisher)['findings'])
            self.assertNotIn('package_publisher_mismatch', rules, publisher)
        rules = _rules(
            analyze_signature(self.tmp, 'CN=Contoso, C=US')['findings'])
        self.assertIn('package_publisher_mismatch', rules)

    def test_publisher_mismatch_and_expired(self):
        other = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Attacker')])
        _write_p7x(self.tmp, other, expired=True)
        rules = _rules(analyze_signature(self.tmp, PUBLISHER)['findings'])
        self.assertEqual(
            rules['package_publisher_mismatch']['severity'], 'high')
        self.assertIn('package_certificate_expired', rules)


class StringsTests(SimpleTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ascii_and_utf16(self):
        path = self.tmp / 'bin.dll'
        path.write_bytes(
            b'\x00\x01https://ascii.example/path\x00\x02'
            + 'https://wide.example/x'.encode('utf-16-le')
            + b'\x00\x00short\x00')
        strings = extract_strings(path, 100)
        self.assertIn('https://ascii.example/path', strings)
        self.assertIn('https://wide.example/x', strings)
        self.assertNotIn('short', strings)

    def test_chunk_boundary_no_duplicates(self):
        path = self.tmp / 'big.dll'
        token = b'boundary_string_value_123'
        with mock.patch(
                'mobsf.StaticAnalyzer.views.windows.strings.CHUNK_SIZE',
                64 * 1024):
            pad = 64 * 1024 - 10
            path.write_bytes(b'\x00' * pad + token + b'\x00' * 100)
            strings = extract_strings(path, 100)
        self.assertEqual(strings, [token.decode()])

    def test_utf16_split_at_chunk_boundary(self):
        path = self.tmp / 'wide.dll'
        url = 'https://wide.example/path/to/resource'
        chunk = 64 * 1024
        data = bytearray(chunk * 2)
        offset = chunk - 21
        encoded = url.encode('utf-16-le')
        data[offset:offset + len(encoded)] = encoded
        path.write_bytes(bytes(data))
        with mock.patch(
                'mobsf.StaticAnalyzer.views.windows.strings.CHUNK_SIZE',
                chunk):
            self.assertEqual(extract_strings(path, 100), [url])

    def test_long_run_across_boundary_keeps_prefix(self):
        path = self.tmp / 'long.dll'
        chunk = 64 * 1024
        url = b'https://long.example/'
        start = chunk - 10000
        data = (b'\x00' * start + url + b'A' * 20000 + b'\x00')
        path.write_bytes(data)
        with mock.patch(
                'mobsf.StaticAnalyzer.views.windows.strings.CHUNK_SIZE',
                chunk):
            strings = extract_strings(path, 100)
        self.assertEqual(len(strings), 1)
        self.assertTrue(strings[0].startswith(url.decode()))

    def test_limits(self):
        path = self.tmp / 'many.dll'
        path.write_bytes(b''.join(
            f'string_number_{i:05d}\x00'.encode() for i in range(500)))
        self.assertEqual(len(extract_strings(path, 10)), 10)
        self.assertEqual(extract_strings(path, 1000, max_bytes=0), [])


class PackageHelperTests(SimpleTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _bundle_manifest(self, packages):
        meta = self.tmp / 'AppxMetadata'
        meta.mkdir()
        body = ''.join(
            f'<Package Type="{t}" FileName="{n}" Architecture="{a}"/>'
            for t, n, a in packages)
        (meta / 'AppxBundleManifest.xml').write_text(
            '<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle">'
            f'<Packages>{body}</Packages></Bundle>')

    def test_bundle_selects_preferred_arch(self):
        self._bundle_manifest([
            ('application', 'App_x86.msix', 'x86'),
            ('resource', 'App_en.msix', 'neutral'),
            ('application', 'App_x64.msix', 'x64'),
        ])
        for name in ('App_x86.msix', 'App_en.msix', 'App_x64.msix'):
            (self.tmp / name).write_bytes(b'PK')
        selected = windows._select_bundle_package(self.tmp)
        self.assertEqual(selected.name, 'App_x64.msix')

    def test_bundle_rejects_traversal_and_links(self):
        outside = Path(tempfile.mkdtemp())
        try:
            (outside / 'evil.appx').write_bytes(b'PK')
            (self.tmp / 'link.appx').symlink_to(outside / 'evil.appx')
            self._bundle_manifest([
                ('application', '../evil.appx', 'x64'),
                ('application', 'link.appx', 'x64'),
                ('application', 'App.exe', 'x64'),
            ])
            (self.tmp / 'App.exe').write_bytes(b'MZ')
            self.assertIsNone(windows._select_bundle_package(self.tmp))
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_iter_pe_files(self):
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'App.exe').write_bytes(b'MZ' + b'\x00' * 10)
        (self.tmp / 'a.dll').write_bytes(b'MZ' + b'\x00' * 10)
        (self.tmp / 'fake.dll').write_bytes(b'NOTPE')
        (self.tmp / 'link.dll').symlink_to(self.tmp / 'a.dll')
        found = [rel for _, rel in windows._iter_pe_files(
            self.tmp, ['bin\\App.exe'])]
        self.assertEqual(found, ['bin/App.exe', 'a.dll'])

    def test_pdb_finding(self):
        findings = windows._package_file_findings(['App.exe', 'App.pdb'])
        self.assertEqual(findings[0]['rule'], 'debug_symbols_packaged')
        self.assertEqual(windows._package_file_findings(['App.exe']), [])


class PEChecksecTests(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp = Path(tempfile.mkdtemp())
        with zipfile.ZipFile(SAMPLE) as zf:
            names = [n for n in zf.namelist()
                     if n.lower().endswith(('.exe', '.dll'))]
            cls.binary = names[0]
            zf.extract(cls.binary, cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        super().tearDownClass()

    def test_il_only_binary(self):
        result = PEChecksec(self.tmp / self.binary, self.binary).checksec()
        self.assertEqual(result['name'], self.binary)
        for key in ('aslr', 'high_entropy_va', 'dep', 'cfg', 'safe_seh',
                    'stack_cookie', 'rwx_sections', 'code_signature',
                    'banned_imports'):
            self.assertIn('severity', result[key])
        self.assertIn('.NET', result['runtime'])
        self.assertEqual(result['cfg']['value'], NA)
        self.assertEqual(result['banned_imports']['value'], NA)

    def test_non_pe_returns_empty(self):
        path = self.tmp / 'notpe.dll'
        path.write_bytes(b'MZ' + b'\x00' * 64)
        self.assertFalse(PEChecksec(path, 'notpe.dll').checksec())


class AnalyzePackageTests(TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @mock.patch(
        'mobsf.StaticAnalyzer.views.windows.windows.MalwareDomainCheck')
    def test_sample_appx(self, mdc):
        mdc.return_value.scan.return_value = {}
        checksum = 'a' * 32
        app_dir = self.tmp / checksum
        app_dir.mkdir()
        app_path = app_dir / f'{checksum}.appx'
        shutil.copy(SAMPLE, app_path)
        analysis = windows.analyze_package(
            checksum, app_path, app_dir, 'appx', 'windows.appx')
        self.assertTrue(analysis['manifest']['package_name'])
        self.assertTrue(analysis['signature']['signed'])
        self.assertTrue(analysis['pe_analysis'])
        self.assertIn('AppxManifest.xml', analysis['files'])
        context = get_context_from_analysis(analysis)
        self.assertEqual(context['package_type'], 'appx')
        self.assertEqual(context['md5'], checksum)
        self.assertTrue(context['pe_analysis'])
