"""Build a signed APK containing Frida Gadget."""
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
import zipfile
from pathlib import Path
from tempfile import gettempdir
from xml.etree import ElementTree as XmlElementTree

from defusedxml import ElementTree

from django.conf import settings

from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.views.common.frida.server_update import (
    FridaServerUpdater,
)
from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    find_java_binary,
    is_file_exists,
    sha256,
)

logger = logging.getLogger(__name__)
ANDROID_NS = 'http://schemas.android.com/apk/res/android'
ANDROID_ATTR = f'{{{ANDROID_NS}}}'
SUPPORTED_ABIS = {
    'armeabi': ('arm', 'armeabi'),
    'armeabi-v7a': ('arm', 'armeabi-v7a'),
    'arm64-v8a': ('arm64', 'arm64-v8a'),
    'x86': ('x86', 'x86'),
    'x86_64': ('x86_64', 'x86_64'),
}


class GadgetPatcher:
    """Create an independently signed, single-ABI Gadget APK."""

    _keystore_lock = threading.Lock()
    _patch_lock = threading.Lock()

    def __init__(self, app_dir, apk_file, android_abi) -> None:
        self.app_dir = Path(app_dir).resolve()
        self.apk_file = Path(apk_file).resolve()
        self.android_abi = android_abi
        self.work_dir = self.app_dir / 'apktool_gadget'
        self.unsigned_apk = self.app_dir / 'mobsf-gadget-unsigned.apk'
        self.output_apk = self.app_dir / 'mobsf-gadget.apk'
        static_tools = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'
        if (settings.APKTOOL_BINARY
                and is_file_exists(settings.APKTOOL_BINARY)):
            self.apktool_path = Path(settings.APKTOOL_BINARY)
        else:
            self.apktool_path = static_tools / 'apktool_3.0.3.jar'
        self.apksigner_path = static_tools / 'apksigner.jar'

    def _validate(self):
        """Validate fixed inputs and required existing tools."""
        if self.apk_file.suffix.lower() != '.apk':
            raise ValueError('Frida Gadget requires a single APK')
        if not is_safe_path(
                self.app_dir, self.apk_file, self.apk_file.name):
            raise ValueError('APK is outside its analysis directory')
        if not self.apk_file.is_file() or is_pipe_or_link(self.apk_file):
            raise ValueError('APK is not a regular file')
        if self.android_abi not in SUPPORTED_ABIS:
            raise ValueError(
                f'Unsupported Android architecture: {self.android_abi}')
        for tool in (self.apktool_path, self.apksigner_path):
            if not tool.is_file() or is_pipe_or_link(tool):
                raise RuntimeError(
                    f'Required Android tool is missing: {tool.name}')
        if self.work_dir.is_symlink():
            raise ValueError('Unsafe APK patching workspace')

    def _run(self, args, action, env=None):
        """Run a bounded build command without invoking a shell."""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                check=False,
                env=env,
                timeout=settings.BINARY_ANALYSIS_TIMEOUT,
            )
        except subprocess.TimeoutExpired as exp:
            raise RuntimeError(f'{action} timed out') from exp
        if result.returncode != 0:
            logger.error(
                '%s failed with exit code %d',
                action,
                result.returncode,
            )
            raise RuntimeError(f'{action} failed')
        return result.stdout

    def _decompile(self):
        """Decode resources and smali with the existing apktool."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)
        args = [
            find_java_binary(),
            '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
            '-jar',
            self.apktool_path.as_posix(),
            'decode',
            '--force',
            '--frame-path',
            gettempdir(),
            self.apk_file.as_posix(),
            '--output',
            self.work_dir.as_posix(),
        ]
        self._run(args, 'APK decoding')

    @staticmethod
    def _qualified_class_name(package, class_name):
        """Resolve an Android manifest class name."""
        if not class_name:
            return 'android.app.Application'
        if class_name.startswith('.'):
            return f'{package}{class_name}'
        if '.' not in class_name:
            return f'{package}.{class_name}'
        return class_name

    def _inject_loader(self):
        """Load Gadget from the app class or a generated subclass."""
        manifest = self.work_dir / 'AndroidManifest.xml'
        if not manifest.is_file() or is_pipe_or_link(manifest):
            raise RuntimeError('Decoded Android manifest is missing')
        tree = ElementTree.parse(manifest)
        root = tree.getroot()
        package = root.get('package', '')
        application = root.find('application')
        if not package or application is None:
            raise RuntimeError('Android manifest has no application')
        if root.get(f'{ANDROID_ATTR}sharedUserId'):
            raise ValueError('Shared-user APKs cannot be safely re-signed')
        original = self._qualified_class_name(
            package,
            application.get(f'{ANDROID_ATTR}name'),
        )
        class_pattern = r'(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*'
        if not re.fullmatch(class_pattern, original):
            raise ValueError('Unsupported Android Application class name')
        digest = sha256(self.apk_file)[:12]
        if not self._inject_existing_application(original):
            loader = f'com.mobsf.g{digest}.MobSFApplication'
            loader_type = f'L{loader.replace(".", "/")};'
            parent_type = f'L{original.replace(".", "/")};'
            application.set(f'{ANDROID_ATTR}name', loader)
            smali = self.work_dir / 'smali' / Path(*loader.split('.'))
            smali = smali.with_suffix('.smali')
            smali.parent.mkdir(parents=True, exist_ok=True)
            smali.write_text(
                '\n'.join((
                    f'.class public {loader_type}',
                    f'.super {parent_type}',
                    '',
                    '.method static constructor <clinit>()V',
                    '    .locals 1',
                    '    const-string v0, "frida-gadget"',
                    '    invoke-static {v0}, '
                    'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
                    '    return-void',
                    '.end method',
                    '',
                    '.method public constructor <init>()V',
                    '    .locals 0',
                    f'    invoke-direct {{p0}}, {parent_type}-><init>()V',
                    '    return-void',
                    '.end method',
                    '',
                )),
                encoding='utf-8',
            )
        application.set(f'{ANDROID_ATTR}extractNativeLibs', 'true')
        self.user_ca_trusted = False
        network_config = application.get(
            f'{ANDROID_ATTR}networkSecurityConfig')
        if not network_config:
            config_name = f'mobsf_network_security_{digest}'
            network_config = f'@xml/{config_name}'
            application.set(
                f'{ANDROID_ATTR}networkSecurityConfig',
                network_config,
            )
            config_dir = self.work_dir / 'res' / 'xml'
            config_dir.mkdir(parents=True, exist_ok=True)
            network_security = (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<network-security-config>\n'
                '    <base-config>\n'
                '        <trust-anchors>\n'
                '            <certificates src="system" />\n'
                '            <certificates src="user" />\n'
                '        </trust-anchors>\n'
                '    </base-config>\n'
                '</network-security-config>\n'
            )
            (config_dir / f'{config_name}.xml').write_text(
                network_security,
                encoding='utf-8',
            )
            self.user_ca_trusted = True
        else:
            logger.warning(
                'Preserving the application network security config; '
                'user CA trust depends on the application policy')
        XmlElementTree.register_namespace('android', ANDROID_NS)
        tree.write(
            manifest,
            encoding='utf-8',
            xml_declaration=True,
        )
        return package

    def _inject_existing_application(self, class_name):
        """Inject a load call into an existing Application smali class."""
        relative = Path(*class_name.split('.')).with_suffix('.smali')
        application_smali = None
        for smali_dir in self.work_dir.glob('smali*'):
            candidate = smali_dir / relative
            if candidate.is_file() and not candidate.is_symlink():
                application_smali = candidate
                break
        if not application_smali:
            return False
        source = application_smali.read_text('utf-8', 'ignore')
        if re.search(r'const-string \S+, "frida-gadget"', source):
            raise ValueError(
                'Application already contains a Frida Gadget loader')
        method = re.search(
            r'(?ms)^\.method[^\n]* static constructor <clinit>\(\)V\n'
            r'(?P<body>.*?)^\.end method',
            source,
        )
        if not method:
            source += (
                '\n.method static constructor <clinit>()V\n'
                '    .locals 1\n'
                '    const-string v0, "frida-gadget"\n'
                '    invoke-static {v0}, '
                'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                '    return-void\n'
                '.end method\n'
            )
        else:
            body = method.group('body')
            registers = re.search(
                r'(?m)^(?P<indent>\s*)\.(?P<kind>locals|registers) '
                r'(?P<count>\d+)\s*$',
                body,
            )
            if not registers:
                raise ValueError(
                    'Unsupported Application static initializer')
            register = int(registers.group('count'))
            directive = (
                f'{registers.group("indent")}.{registers.group("kind")} '
                f'{register + 1}'
            )
            load_call = (
                f'\n    const-string v{register}, "frida-gadget"\n'
                f'    invoke-static {{v{register}}}, '
                'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'
            )
            body = (
                body[:registers.start()]
                + directive
                + load_call
                + body[registers.end():]
            )
            source = source[:method.start('body')] + body + source[method.end('body'):]
        application_smali.write_text(source, encoding='utf-8')
        return True

    def _install_gadget(self):
        """Copy the matched Gadget and its fixed local-only config."""
        frida_arch, android_abi = SUPPORTED_ABIS[self.android_abi]
        updater = FridaServerUpdater('android', frida_version)
        if not updater.update_frida_gadget(frida_arch):
            raise RuntimeError('Unable to obtain a matching Frida Gadget')
        cached = (
            Path(settings.DWD_DIR)
            / f'frida-gadget-{frida_version}-android-{frida_arch}.so'
        )
        with cached.open('rb') as binary:
            if binary.read(4) != b'\x7fELF':
                raise RuntimeError('Cached Frida Gadget is invalid')
        library_dir = self.work_dir / 'lib' / android_abi
        library_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cached, library_dir / 'libfrida-gadget.so')
        config = {
            'interaction': {
                'type': 'listen',
                'address': '127.0.0.1',
                'port': 27042,
                'on_load': 'resume',
            },
        }
        config_file = library_dir / 'libfrida-gadget.config.so'
        config_file.write_text(
            json.dumps(config, separators=(',', ':')),
            encoding='utf-8',
        )

    def _build(self):
        """Rebuild the decoded APK."""
        args = [
            find_java_binary(),
            '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
            '-jar',
            self.apktool_path.as_posix(),
            'build',
            '--force',
            self.work_dir.as_posix(),
            '--output',
            self.unsigned_apk.as_posix(),
        ]
        self._run(args, 'APK rebuilding')

    @staticmethod
    def _keytool_path():
        """Return keytool from the configured Java runtime."""
        java = Path(find_java_binary())
        executable = 'keytool.exe' if os.name == 'nt' else 'keytool'
        sibling = java.with_name(executable)
        if sibling.is_file():
            return sibling.as_posix()
        keytool = shutil.which(executable)
        if keytool:
            return keytool
        raise RuntimeError('keytool is required to create the MobSF lab key')

    def _signing_credentials(self):
        """Create or load the local lab signing key."""
        download_dir = Path(settings.DWD_DIR)
        download_dir.mkdir(parents=True, exist_ok=True)
        credentials_file = download_dir / 'mobsf-dynamic-signing.json'
        keystore = download_dir / 'mobsf-dynamic-signing.p12'
        with self._keystore_lock:
            if keystore.exists() and not credentials_file.exists():
                raise RuntimeError(
                    'MobSF signing credentials are missing')
            if credentials_file.exists():
                if is_pipe_or_link(credentials_file):
                    raise RuntimeError('Unsafe MobSF signing credentials')
                credentials = json.loads(
                    credentials_file.read_text(encoding='utf-8'))
                password = credentials.get('password')
                if not isinstance(password, str) or len(password) < 32:
                    raise RuntimeError('Invalid MobSF signing credentials')
                os.chmod(credentials_file, 0o600)
            else:
                password = secrets.token_urlsafe(36)
                descriptor = os.open(
                    credentials_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
                    json.dump({'password': password}, target)
            if keystore.exists():
                if is_pipe_or_link(keystore):
                    raise RuntimeError('Unsafe MobSF signing keystore')
                os.chmod(keystore, 0o600)
                return keystore, password
            env = os.environ.copy()
            env['MOBSF_KEYSTORE_PASSWORD'] = password
            args = [
                self._keytool_path(),
                '-genkeypair',
                '-keystore',
                keystore.as_posix(),
                '-storetype',
                'PKCS12',
                '-storepass:env',
                'MOBSF_KEYSTORE_PASSWORD',
                '-keypass:env',
                'MOBSF_KEYSTORE_PASSWORD',
                '-alias',
                'mobsf-dynamic',
                '-keyalg',
                'RSA',
                '-keysize',
                '3072',
                '-validity',
                '10000',
                '-dname',
                'CN=MobSF Dynamic Analysis, O=MobSF',
                '-noprompt',
            ]
            try:
                self._run(args, 'Lab keystore generation', env)
            except Exception:
                credentials_file.unlink(missing_ok=True)
                keystore.unlink(missing_ok=True)
                raise
            os.chmod(keystore, 0o600)
            return keystore, password

    def _sign(self):
        """Sign and verify the rebuilt APK with the local lab key."""
        keystore, password = self._signing_credentials()
        env = os.environ.copy()
        env['MOBSF_KEYSTORE_PASSWORD'] = password
        sign = [
            find_java_binary(),
            '-jar',
            self.apksigner_path.as_posix(),
            'sign',
            '--ks',
            keystore.as_posix(),
            '--ks-key-alias',
            'mobsf-dynamic',
            '--ks-pass',
            'env:MOBSF_KEYSTORE_PASSWORD',
            '--key-pass',
            'env:MOBSF_KEYSTORE_PASSWORD',
            '--out',
            self.output_apk.as_posix(),
            self.unsigned_apk.as_posix(),
        ]
        self._run(sign, 'APK signing', env)
        verify = [
            find_java_binary(),
            '-jar',
            self.apksigner_path.as_posix(),
            'verify',
            '--verbose',
            self.output_apk.as_posix(),
        ]
        self._run(verify, 'APK signature verification')

    def _verify_artifact(self):
        """Verify the expected Gadget files are present."""
        _, android_abi = SUPPORTED_ABIS[self.android_abi]
        expected = {
            'AndroidManifest.xml',
            f'lib/{android_abi}/libfrida-gadget.so',
            f'lib/{android_abi}/libfrida-gadget.config.so',
        }
        with zipfile.ZipFile(self.output_apk) as apk:
            if not expected.issubset(apk.namelist()):
                raise RuntimeError('Signed APK is missing Frida Gadget files')

    def patch(self):
        """Build, sign, and return a Frida Gadget APK."""
        with self._patch_lock:
            return self._patch()

    def _patch(self):
        """Run the serialized Gadget build."""
        logger.info('Validating APK for Frida Gadget injection')
        self._validate()
        self.output_apk.unlink(missing_ok=True)
        self.unsigned_apk.unlink(missing_ok=True)
        try:
            logger.info('Decoding APK resources and bytecode')
            self._decompile()
            logger.info('Injecting the Frida Gadget application loader')
            package = self._inject_loader()
            logger.info(
                'Preparing Frida Gadget for Android ABI %s',
                self.android_abi,
            )
            self._install_gadget()
            logger.info('Rebuilding the Frida Gadget APK')
            self._build()
            logger.info('Signing the Frida Gadget APK with the MobSF lab key')
            self._sign()
            logger.info('Verifying the signed Frida Gadget APK')
            self._verify_artifact()
            logger.info('Built Frida Gadget APK for %s', package)
            return self.output_apk
        except Exception:
            self.output_apk.unlink(missing_ok=True)
            raise
        finally:
            self.unsigned_apk.unlink(missing_ok=True)
            if self.work_dir.exists() and not self.work_dir.is_symlink():
                shutil.rmtree(self.work_dir)
