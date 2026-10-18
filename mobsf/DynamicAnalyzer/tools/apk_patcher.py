"""Build a signed APK containing Frida Gadget."""
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import threading
import weakref
import zipfile
from pathlib import Path
from tempfile import gettempdir
from xml.etree import ElementTree as XmlElementTree

from defusedxml import ElementTree

from django.conf import settings

from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.tools.webproxy import get_ca_file
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
from mobsf.StaticAnalyzer.tools.androguard4 import apk as androguard_apk

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
PATCH_METADATA = 'assets/mobsf/gadget.json'
PATCH_SCHEMA = 1


class GadgetPatcher:
    """Create an independently signed, single-ABI Gadget APK."""

    _keystore_lock = threading.Lock()
    _patch_locks = weakref.WeakValueDictionary()
    _patch_locks_guard = threading.Lock()

    @staticmethod
    def apk_abis(apk_file):
        """Return native ABIs present in an APK."""
        with zipfile.ZipFile(apk_file) as apk:
            return {
                parts[1]
                for name in apk.namelist()
                if len(parts := Path(name).parts) >= 3
                and parts[0] == 'lib'
                and parts[1] in SUPPORTED_ABIS
            }

    @classmethod
    def select_abi(cls, apk_file, device_abis, split_apks=None):
        """Select an ABI supported by both the device and APK."""
        app_abis = cls.apk_abis(apk_file)
        for split_apk in split_apks or ():
            app_abis.update(cls.apk_abis(split_apk))
        for abi in device_abis:
            if abi in SUPPORTED_ABIS and (
                    not app_abis or abi in app_abis):
                return abi
        raise ValueError(
            'APK native libraries are incompatible with the Android device')

    @staticmethod
    def find_split_apks(app_dir, base_apk):
        """Find regular sibling APKs retained by static analysis."""
        app_dir = Path(app_dir).resolve()
        base_apk = Path(base_apk).resolve()
        splits = []
        for candidate in app_dir.rglob('*.apk'):
            candidate = candidate.resolve()
            if (candidate == base_apk
                    or candidate.name in (
                        'mobsf-gadget.apk',
                        'mobsf-gadget-unsigned.apk',
                    )
                    or 'mobsf-gadget-splits' in candidate.parts):
                continue
            relative = candidate.relative_to(app_dir).as_posix()
            if (not is_safe_path(
                    app_dir, candidate, relative)
                    or not candidate.is_file()
                    or is_pipe_or_link(candidate)):
                raise ValueError('Invalid split APK path')
            splits.append(candidate)
        return tuple(sorted(splits))

    @classmethod
    def compatible_splits(cls, split_apks, selected_abi):
        """Filter ABI configuration splits for the selected device ABI."""
        abi_tokens = {
            'armeabi': 'armeabi',
            'armeabi-v7a': 'armeabi_v7a',
            'arm64-v8a': 'arm64_v8a',
            'x86': 'x86',
            'x86_64': 'x86_64',
        }
        selected_token = abi_tokens[selected_abi]
        compatible = []
        for split_apk in split_apks:
            native_abis = cls.apk_abis(split_apk)
            if native_abis and selected_abi not in native_abis:
                continue
            stem = split_apk.stem.lower().replace('-', '_')
            config_tokens = {
                token for token in abi_tokens.values()
                if re.search(
                    rf'(?:^|[._])config[._]{re.escape(token)}(?:$|[.])',
                    stem,
                )
            }
            if config_tokens and selected_token not in config_tokens:
                continue
            compatible.append(split_apk)
        return tuple(compatible)

    def __init__(
            self, app_dir, apk_file, android_abi,
            replace_existing_gadget=False, split_apks=None) -> None:
        self.app_dir = Path(app_dir).resolve()
        self.apk_file = Path(apk_file).resolve()
        self.android_abi = android_abi
        self.replace_existing_gadget = replace_existing_gadget
        self.split_apks = tuple(
            Path(path).resolve() for path in (split_apks or ()))
        self.no_resource_rebuild = bool(self.split_apks)
        self.root_ca_embedded = not self.no_resource_rebuild
        self.work_dir = self.app_dir / 'apktool_gadget'
        self.unsigned_apk = self.app_dir / 'mobsf-gadget-unsigned.apk'
        self.output_apk = self.app_dir / 'mobsf-gadget.apk'
        self.split_output_dir = self.app_dir / 'mobsf-gadget-splits'
        self.install_apks = []
        static_tools = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'
        if (settings.APKTOOL_BINARY
                and is_file_exists(settings.APKTOOL_BINARY)):
            self.apktool_path = Path(settings.APKTOOL_BINARY)
        else:
            self.apktool_path = static_tools / 'apktool_3.0.3.jar'
        self.apksigner_path = static_tools / 'apksigner.jar'
        self.patch_metadata = None

    @staticmethod
    def inspect(apk_file):
        """Identify MobSF or unknown Frida Gadget injection."""
        apk_file = Path(apk_file)
        if not apk_file.is_file() or is_pipe_or_link(apk_file):
            raise ValueError('APK is not a regular file')
        try:
            with zipfile.ZipFile(apk_file) as apk:
                names = set(apk.namelist())
                if PATCH_METADATA in names:
                    metadata_info = apk.getinfo(PATCH_METADATA)
                    if metadata_info.file_size > 65536:
                        raise ValueError('MobSF Gadget metadata is too large')
                    metadata = json.loads(
                        apk.read(PATCH_METADATA).decode('utf-8'))
                    if (not isinstance(metadata, dict)
                            or metadata.get('schema') != PATCH_SCHEMA
                            or metadata.get('producer') != 'MobSF'):
                        raise ValueError('Invalid MobSF Gadget metadata')
                    return 'mobsf', metadata
                gadget = any(
                    name.endswith('/libfrida-gadget.so')
                    for name in names
                )
                return ('third_party', None) if gadget else ('none', None)
        except (OSError, zipfile.BadZipFile, UnicodeDecodeError,
                json.JSONDecodeError) as exp:
            raise ValueError('Unable to inspect APK Gadget metadata') from exp

    def _target_sdk(self, manifest):
        """Return the effective target SDK of the decoded APK."""
        sdk = {}
        uses_sdk = manifest.find('uses-sdk')
        if uses_sdk is not None:
            for key in ('minSdkVersion', 'targetSdkVersion'):
                sdk[key] = uses_sdk.get(f'{ANDROID_ATTR}{key}')
        # Apktool moves SDK versions from the manifest into apktool.yml.
        apktool_yml = self.work_dir / 'apktool.yml'
        if apktool_yml.is_file() and not apktool_yml.is_symlink():
            text = apktool_yml.read_text('utf-8', 'ignore')
            for key in ('minSdkVersion', 'targetSdkVersion'):
                match = re.search(
                    rf'^\s*{key}:\s*[\'"]?(\d+)[\'"]?\s*$',
                    text,
                    re.MULTILINE,
                )
                if match and not sdk.get(key):
                    sdk[key] = match.group(1)
        for key in ('targetSdkVersion', 'minSdkVersion'):
            try:
                return int(sdk[key])
            except (KeyError, TypeError, ValueError):
                continue
        return 1

    @staticmethod
    def validate_archive_size(apk_file):
        """Apply MobSF expansion limits before apktool decoding."""
        total = 0
        with zipfile.ZipFile(apk_file) as apk:
            for member in apk.infolist():
                if member.is_dir():
                    continue
                if (member.file_size
                        > settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE):
                    raise ValueError(
                        'APK entry exceeds the uncompressed size limit')
                total += member.file_size
                if total > settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE:
                    raise ValueError(
                        'APK exceeds the total uncompressed size limit')

    def _validate(self):
        """Validate fixed inputs and required existing tools."""
        if self.apk_file.suffix.lower() != '.apk':
            raise ValueError('Frida Gadget requires a single APK')
        if not is_safe_path(
                self.app_dir, self.apk_file, self.apk_file.name):
            raise ValueError('APK is outside its analysis directory')
        if not self.apk_file.is_file() or is_pipe_or_link(self.apk_file):
            raise ValueError('APK is not a regular file')
        if (self.apk_file in (self.output_apk, self.unsigned_apk)
                or self.apk_file == self.work_dir
                or self.work_dir in self.apk_file.parents):
            raise ValueError('APK overlaps the Gadget build workspace')
        if self.android_abi not in SUPPORTED_ABIS:
            raise ValueError(
                f'Unsupported Android architecture: {self.android_abi}')
        self.validate_archive_size(self.apk_file)
        for split_apk in self.split_apks:
            if (split_apk.suffix.lower() != '.apk'
                    or not is_safe_path(
                        self.app_dir, split_apk, split_apk.name)
                    or not split_apk.is_file()
                    or is_pipe_or_link(split_apk)
                    or split_apk == self.apk_file):
                raise ValueError('Invalid split APK input')
        if self.split_apks:
            base_manifest = androguard_apk.APK(
                self.apk_file.as_posix())
            base_package = base_manifest.get_package()
            base_version = base_manifest.get_androidversion_code()
            for split_apk in self.split_apks:
                split_manifest = androguard_apk.APK(
                    split_apk.as_posix())
                split_name = split_manifest.get_attribute_value(
                    'manifest', 'split')
                if (not split_name
                        or split_manifest.get_package() != base_package
                        or split_manifest.get_androidversion_code()
                        != base_version):
                    raise ValueError(
                        'Split APK package metadata does not match the base')
        gadget_state, metadata = self.inspect(self.apk_file)
        if gadget_state == 'third_party' and not self.replace_existing_gadget:
            raise ValueError(
                'APK contains an unknown Frida Gadget injection')
        self.gadget_state = gadget_state
        self.patch_metadata = metadata
        self.app_abis = self.apk_abis(self.apk_file)
        for split_apk in self.split_apks:
            self.app_abis.update(self.apk_abis(split_apk))
        if self.app_abis and self.android_abi not in self.app_abis:
            raise ValueError(
                'APK native libraries are incompatible with the '
                f'selected ABI: {self.android_abi}')
        for tool in (self.apktool_path, self.apksigner_path):
            if not tool.is_file() or is_pipe_or_link(tool):
                raise RuntimeError(
                    f'Required Android tool is missing: {tool.name}')
        if self.work_dir.is_symlink():
            raise ValueError('Unsafe APK patching workspace')
        if self.split_output_dir.is_symlink():
            raise ValueError('Unsafe Gadget split output directory')

    def _run(self, args, action, env=None):
        """Run a bounded build command without invoking a shell."""
        process_options = {}
        if os.name == 'nt':
            process_options['creationflags'] = (
                subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            process_options['start_new_session'] = True
        process = subprocess.Popen(
            args,
            env=env,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            **process_options,
        )
        try:
            stdout, _ = process.communicate(
                timeout=settings.BINARY_ANALYSIS_TIMEOUT,
            )
        except subprocess.TimeoutExpired as exp:
            self._kill_process_tree(process)
            raise RuntimeError(f'{action} timed out') from exp
        if process.returncode != 0:
            logger.error(
                '%s failed with exit code %d',
                action,
                process.returncode,
            )
            raise RuntimeError(f'{action} failed')
        return stdout

    @staticmethod
    def _kill_process_tree(process):
        """Terminate a timed-out build and all of its descendants."""
        if os.name == 'nt':
            try:
                subprocess.run(
                    [
                        'taskkill',
                        '/F',
                        '/T',
                        '/PID',
                        str(process.pid),
                    ],
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                process.kill()
        for pipe in (process.stdout, process.stderr):
            if pipe:
                pipe.close()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

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
        ]
        if self.no_resource_rebuild:
            args.append('--no-res')
        args.extend([
            '--frame-path',
            gettempdir(),
            self.apk_file.as_posix(),
            '--output',
            self.work_dir.as_posix(),
        ])
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

    @staticmethod
    def _application_process(package, application):
        """Return the validated primary process name."""
        process = application.get(f'{ANDROID_ATTR}process') or package
        if process.startswith(':'):
            process = f'{package}{process}'
        if not re.fullmatch(r'[A-Za-z0-9_.:]+', process):
            raise ValueError('Unsupported Android application process name')
        return process

    def _gadget_load_smali(self, process):
        """Return a primary-process-only Gadget load sequence."""
        label = f'mobsf_{sha256(self.apk_file)[:12]}'
        return (
            '    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I',
            '    const/16 v1, 0x1c',
            f'    if-lt v0, v1, :{label}_legacy',
            '    invoke-static {}, '
            'Landroid/app/Application;->getProcessName()'
            'Ljava/lang/String;',
            '    move-result-object v0',
            f'    goto :{label}_check',
            '',
            f'    :{label}_legacy',
            '    invoke-static {}, '
            'Landroid/app/ActivityThread;->currentProcessName()'
            'Ljava/lang/String;',
            '    move-result-object v0',
            '',
            f'    :{label}_check',
            f'    const-string v1, "{process}"',
            '    invoke-virtual {v1, v0}, '
            'Ljava/lang/String;->equals(Ljava/lang/Object;)Z',
            '    move-result v0',
            f'    if-eqz v0, :{label}_done',
            '    const-string v1, "frida-gadget"',
            '    invoke-static {v1}, '
            'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
            '',
            f'    :{label}_done',
        )

    def _inject_loader(self):
        """Load Gadget from the app class or a generated subclass."""
        if self.no_resource_rebuild:
            return self._inject_split_loader()
        manifest = self.work_dir / 'AndroidManifest.xml'
        if not manifest.is_file() or is_pipe_or_link(manifest):
            raise RuntimeError('Decoded Android manifest is missing')
        tree = ElementTree.parse(manifest)
        root = tree.getroot()
        package = root.get('package', '')
        application = root.find('application')
        if not package or application is None:
            raise RuntimeError('Android manifest has no application')
        if (root.get('split')
                or root.get(f'{ANDROID_ATTR}isSplitRequired') == 'true'):
            raise ValueError(
                'Frida Gadget requires a standalone base APK')
        if root.get(f'{ANDROID_ATTR}sharedUserId'):
            raise ValueError('Shared-user APKs cannot be safely re-signed')
        application.set(f'{ANDROID_ATTR}hasCode', 'true')
        internet_permission = None
        for permission in root.findall('uses-permission'):
            if (permission.get(f'{ANDROID_ATTR}name')
                    == 'android.permission.INTERNET'):
                internet_permission = permission
                break
        if internet_permission is None:
            internet_permission = XmlElementTree.Element(
                'uses-permission')
            internet_permission.set(
                f'{ANDROID_ATTR}name',
                'android.permission.INTERNET',
            )
            root.insert(0, internet_permission)
        internet_permission.attrib.pop(
            f'{ANDROID_ATTR}maxSdkVersion', None)
        original = self._qualified_class_name(
            package,
            application.get(f'{ANDROID_ATTR}name'),
        )
        class_pattern = r'(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*'
        if not re.fullmatch(class_pattern, original):
            raise ValueError('Unsupported Android Application class name')
        digest = sha256(self.apk_file)[:12]
        process = self._application_process(package, application)
        strategy = None
        if self.patch_metadata:
            original_application = self.patch_metadata.get(
                'original_application')
            loader_class = self.patch_metadata.get('loader_class')
            loader_strategy = self.patch_metadata.get('loader_strategy')
            if (not isinstance(original_application, str)
                    or not re.fullmatch(class_pattern, original_application)
                    or not isinstance(loader_class, str)
                    or not re.fullmatch(class_pattern, loader_class)
                    or loader_strategy not in (
                        'existing_application',
                        'generated_application',
                        'existing_gadget',
            )
                    or loader_class != original):
                raise ValueError('Invalid MobSF Gadget loader metadata')
            loader_smali = self._find_application_smali(loader_class)
            if (not loader_smali
                    or '"frida-gadget"' not in loader_smali.read_text(
                        'utf-8', 'ignore')):
                raise ValueError('MobSF Gadget loader is missing')
            self.original_application = original_application
            self.loader_class = loader_class
            self.loader_strategy = loader_strategy
        else:
            strategy = self._inject_existing_application(original, process)
            self.original_application = original
            self.loader_class = original
            self.loader_strategy = strategy or 'generated_application'
        if not self.patch_metadata and not strategy:
            loader = f'com.mobsf.g{digest}.MobSFApplication'
            loader_type = f'L{loader.replace(".", "/")};'
            parent_type = f'L{original.replace(".", "/")};'
            application.set(f'{ANDROID_ATTR}name', loader)
            self.loader_class = loader
            smali = self.work_dir / 'smali' / Path(*loader.split('.'))
            smali = smali.with_suffix('.smali')
            smali.parent.mkdir(parents=True, exist_ok=True)
            smali.write_text(
                '\n'.join((
                    f'.class public {loader_type}',
                    f'.super {parent_type}',
                    '',
                    '.method static constructor <clinit>()V',
                    '    .locals 2',
                    *self._gadget_load_smali(process),
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
        self._configure_network_security(root, application, digest)
        XmlElementTree.register_namespace('android', ANDROID_NS)
        tree.write(
            manifest,
            encoding='utf-8',
            xml_declaration=True,
        )
        return package

    def _inject_split_loader(self):
        """Inject Gadget without rebuilding split-dependent resources."""
        parsed_apk = androguard_apk.APK(self.apk_file.as_posix())
        package = parsed_apk.get_package()
        if not package:
            raise ValueError('Unable to read the split APK package')
        if 'android.permission.INTERNET' not in parsed_apk.get_permissions():
            raise ValueError(
                'Split APK Gadget mode requires INTERNET permission '
                'in the original base manifest')
        application = self._qualified_class_name(
            package,
            parsed_apk.get_attribute_value('application', 'name'),
        )
        candidates = [application]
        main_activity = parsed_apk.get_main_activity()
        if main_activity:
            main_activity = self._qualified_class_name(
                package, main_activity)
            if main_activity not in candidates:
                candidates.append(main_activity)
        strategy = None
        loader_class = None
        for candidate in candidates:
            strategy = self._inject_existing_application(candidate)
            if strategy:
                loader_class = candidate
                break
        if not strategy or not loader_class:
            raise ValueError(
                'Split APK has no injectable Application or launcher class')
        self.original_application = application
        self.loader_class = loader_class
        self.loader_strategy = strategy
        self.embedded_ca_resource = None
        self.network_security_resources = ()
        self.root_ca_embedded = False
        logger.warning(
            'Split APK resources are preserved without embedding the '
            'MobSF Root CA; use Frida TLS hooks for interception')
        return package

    @staticmethod
    def _local_xml_tag(element):
        """Return an XML tag without an optional namespace."""
        return element.tag.rsplit('}', 1)[-1]

    def _configure_network_security(self, manifest, application, digest):
        """Embed the MobSF CA and remove XML network-security pins."""
        ca_file = Path(get_ca_file()).resolve()
        if not ca_file.is_file() or is_pipe_or_link(ca_file):
            raise RuntimeError('MobSF Root CA is unavailable')
        ca_digest = sha256(ca_file)[:12]
        ca_name = f'mobsf_ca_{ca_digest}'
        ca_reference = f'@raw/{ca_name}'
        raw_dir = self.work_dir / 'res' / 'raw'
        raw_dir.mkdir(parents=True, exist_ok=True)
        ca_target = raw_dir / f'{ca_name}.pem'
        if ca_target.is_symlink():
            raise ValueError('Unsafe MobSF CA resource path')
        for old_ca in raw_dir.glob('mobsf_ca_*.pem'):
            if old_ca != ca_target:
                if old_ca.is_symlink():
                    raise ValueError('Unsafe previous MobSF CA resource')
                old_ca.unlink()
        shutil.copyfile(ca_file, ca_target)
        self.embedded_ca_resource = f'res/raw/{ca_name}.pem'

        network_config = application.get(
            f'{ANDROID_ATTR}networkSecurityConfig')
        cleartext_policy = application.get(
            f'{ANDROID_ATTR}usesCleartextTraffic')
        if cleartext_policy not in ('true', 'false'):
            target_sdk = self._target_sdk(manifest)
            cleartext_policy = (
                'false' if target_sdk >= 28 else 'true')
        if network_config:
            reference = re.fullmatch(
                r'@(?:[A-Za-z][\w.]*:)?xml/([a-zA-Z0-9_]+)',
                network_config,
            )
            if not reference:
                raise ValueError(
                    'Unsupported Android network security config reference')
            config_name = reference.group(1)
            config_paths = tuple(
                path for path in (self.work_dir / 'res').glob(
                    f'xml*/{config_name}.xml')
                if path.is_file() and not path.is_symlink()
            )
            if not config_paths:
                raise RuntimeError(
                    'Android network security config resource is missing')
        else:
            config_name = f'mobsf_network_security_{digest}'
            application.set(
                f'{ANDROID_ATTR}networkSecurityConfig',
                f'@xml/{config_name}',
            )
            config_dir = self.work_dir / 'res' / 'xml'
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / f'{config_name}.xml'
            root = XmlElementTree.Element('network-security-config')
            XmlElementTree.ElementTree(root).write(
                config_path,
                encoding='utf-8',
                xml_declaration=True,
            )
            config_paths = (config_path,)
        self.network_security_resources = tuple(
            path.relative_to(self.work_dir).as_posix()
            for path in config_paths
        )

        for config_path in config_paths:
            self._patch_network_security_config(
                config_path,
                ca_reference,
                cleartext_policy,
            )
        logger.info(
            'Configured MobSF Root CA trust and XML pin handling')

    def _patch_network_security_config(
            self, config_path, ca_reference, cleartext_policy):
        """Merge the MobSF CA into one network-security resource."""
        tree = ElementTree.parse(config_path)
        root = tree.getroot()
        if self._local_xml_tag(root) != 'network-security-config':
            raise ValueError('Invalid Android network security config')

        removed_pins = 0
        for parent in root.iter():
            for child in tuple(parent):
                if self._local_xml_tag(child) == 'pin-set':
                    parent.remove(child)
                    removed_pins += 1

        base_config = next(
            (child for child in root
             if self._local_xml_tag(child) == 'base-config'),
            None,
        )
        if base_config is None:
            base_config = XmlElementTree.SubElement(
                root,
                'base-config',
                {'cleartextTrafficPermitted': cleartext_policy},
            )

        containers = [
            element for element in root.iter()
            if self._local_xml_tag(element) in (
                'base-config',
                'domain-config',
                'debug-overrides',
            )
        ]
        trusted_configs = 0
        for container in containers:
            anchors = next(
                (child for child in container
                 if self._local_xml_tag(child) == 'trust-anchors'),
                None,
            )
            if anchors is None:
                if container is not base_config:
                    continue
                anchors = XmlElementTree.SubElement(
                    container, 'trust-anchors')
                XmlElementTree.SubElement(
                    anchors,
                    'certificates',
                    {'src': 'system'},
                )
            sources = {
                child.get('src')
                for child in anchors
                if self._local_xml_tag(child) == 'certificates'
            }
            for certificate in tuple(anchors):
                source = certificate.get('src', '')
                if (self._local_xml_tag(certificate) == 'certificates'
                        and source.startswith('@raw/mobsf_ca_')
                        and source != ca_reference):
                    anchors.remove(certificate)
                    sources.discard(source)
            if ca_reference not in sources:
                XmlElementTree.SubElement(
                    anchors,
                    'certificates',
                    {
                        'src': ca_reference,
                        'overridePins': 'true',
                    },
                )
            trusted_configs += 1
        tree.write(
            config_path,
            encoding='utf-8',
            xml_declaration=True,
        )
        return removed_pins, trusted_configs

    def _find_application_smali(self, class_name):
        """Find one decoded application class."""
        relative = Path(*class_name.split('.')).with_suffix('.smali')
        for smali_dir in self.work_dir.glob('smali*'):
            candidate = smali_dir / relative
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        return None

    def _inject_existing_application(self, class_name, process):
        """Inject a load call into an existing Application smali class."""
        application_smali = self._find_application_smali(class_name)
        if not application_smali:
            return None
        source = application_smali.read_text('utf-8', 'ignore')
        if re.search(r'const-string \S+, "frida-gadget"', source):
            if self.replace_existing_gadget:
                return 'existing_gadget'
            raise ValueError('Application contains an unknown Gadget loader')
        method = re.search(
            r'(?ms)^\.method[^\n]* static constructor <clinit>\(\)V\n'
            r'(?P<body>.*?)^\.end method',
            source,
        )
        if not method:
            source += (
                '\n.method static constructor <clinit>()V\n'
                '    .locals 2\n'
                + '\n'.join(self._gadget_load_smali(process))
                + '\n'
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
            register_count = int(registers.group('count'))
            directive = (
                f'{registers.group("indent")}.{registers.group("kind")} '
                f'{max(2, register_count)}'
            )
            load_call = '\n' + '\n'.join(
                self._gadget_load_smali(process))
            body = (
                body[:registers.start()]
                + directive
                + load_call
                + body[registers.end():]
            )
            source = source[:method.start('body')] + body + source[method.end('body'):]
        application_smali.write_text(source, encoding='utf-8')
        return 'existing_application'

    def _install_gadget(self):
        """Copy the matched Gadget and its fixed local-only config."""
        frida_arch, android_abi = SUPPORTED_ABIS[self.android_abi]
        for pattern in (
                'lib/*/libfrida-gadget.so',
                'lib/*/libfrida-gadget.config.so'):
            for previous in self.work_dir.glob(pattern):
                if previous.is_symlink():
                    raise ValueError('Unsafe existing Gadget resource')
                previous.unlink()
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
        lib_root = self.work_dir / 'lib'
        if lib_root.is_dir():
            for abi_dir in lib_root.iterdir():
                if (abi_dir.name in SUPPORTED_ABIS
                        and abi_dir.name != android_abi):
                    if abi_dir.is_symlink():
                        raise ValueError('Unsafe APK native library path')
                    shutil.rmtree(abi_dir)
        library_dir = self.work_dir / 'lib' / android_abi
        library_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cached, library_dir / 'libfrida-gadget.so')
        config = {
            'interaction': {
                'type': 'listen',
                'address': '127.0.0.1',
                'port': 27042,
                'on_load': 'wait',
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
        raise RuntimeError(
            'keytool is required to create the MobSF signing key')

    def _signing_credentials(self):
        """Create or load the MobSF signing key."""
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

    def _signing_certificate_digest(self):
        """Return the SHA-256 identity of the MobSF signing certificate."""
        keystore, password = self._signing_credentials()
        env = os.environ.copy()
        env['MOBSF_KEYSTORE_PASSWORD'] = password
        args = [
            self._keytool_path(),
            '-exportcert',
            '-rfc',
            '-keystore',
            keystore.as_posix(),
            '-storepass:env',
            'MOBSF_KEYSTORE_PASSWORD',
            '-alias',
            'mobsf-dynamic',
        ]
        pem = self._run(args, 'Lab certificate export', env)
        try:
            der = ssl.PEM_cert_to_DER_cert(
                pem.decode('ascii', 'strict'))
        except ValueError as exp:
            raise RuntimeError(
                'Invalid MobSF signing certificate') from exp
        return hashlib.sha256(der).hexdigest()

    def _write_patch_metadata(self, package):
        """Record enough state to refresh a MobSF-patched APK safely."""
        signing_digest = self._signing_certificate_digest()
        previous_signer = (
            self.patch_metadata.get('signing_certificate_sha256')
            if self.patch_metadata else None
        )
        if previous_signer and previous_signer != signing_digest:
            logger.warning(
                'Re-signing a MobSF-patched APK with a different '
                'MobSF signing key')
        metadata = {
            'schema': PATCH_SCHEMA,
            'patch_revision': 3,
            'producer': 'MobSF',
            'package': package,
            'source_apk_sha256': sha256(self.apk_file),
            'frida_version': frida_version,
            'android_abi': self.android_abi,
            'original_application': self.original_application,
            'loader_class': self.loader_class,
            'loader_strategy': self.loader_strategy,
            'ca_resource': self.embedded_ca_resource,
            'network_security_resources': list(
                self.network_security_resources),
            'signing_certificate_sha256': signing_digest,
        }
        metadata_file = self.work_dir / PATCH_METADATA
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        if metadata_file.is_symlink():
            raise ValueError('Unsafe MobSF Gadget metadata path')
        metadata_file.write_text(
            json.dumps(metadata, sort_keys=True, separators=(',', ':')),
            encoding='utf-8',
        )
        self.patch_metadata = metadata

    def _cached_output(self):
        """Return a current patched artifact when no inputs changed."""
        if self.no_resource_rebuild:
            return None
        if (not self.output_apk.is_file()
                or is_pipe_or_link(self.output_apk)):
            return None
        try:
            state, metadata = self.inspect(self.output_apk)
            if state != 'mobsf' or not metadata:
                return None
            ca_digest = sha256(Path(get_ca_file()).resolve())[:12]
            expected_ca = f'res/raw/mobsf_ca_{ca_digest}.pem'
            expected_signer = self._signing_certificate_digest()
            if (
                metadata.get('patch_revision') == 3
                and metadata.get('source_apk_sha256') == sha256(self.apk_file)
                and metadata.get('frida_version') == frida_version
                and metadata.get('android_abi') == self.android_abi
                and metadata.get('ca_resource') == expected_ca
                and metadata.get('signing_certificate_sha256')
                == expected_signer
            ):
                logger.info('Using cached Frida Gadget APK')
                return self.output_apk
        except Exception:
            logger.warning(
                'Ignoring invalid cached Frida Gadget APK')
        return None

    def _sign_apk(self, source_apk, output_apk, label):
        """Sign and verify one APK with the MobSF signing key."""
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
            output_apk.as_posix(),
            source_apk.as_posix(),
        ]
        self._run(sign, f'{label} signing', env)
        verify = [
            find_java_binary(),
            '-jar',
            self.apksigner_path.as_posix(),
            'verify',
            '--verbose',
            output_apk.as_posix(),
        ]
        self._run(verify, f'{label} signature verification')

    def _sign(self):
        """Sign and verify the rebuilt APK with the MobSF signing key."""
        self._sign_apk(
            self.unsigned_apk,
            self.output_apk,
            'APK',
        )

    def _sign_split_apks(self):
        """Re-sign every required split with the MobSF signing key."""
        if not self.split_apks:
            return []
        if self.split_output_dir.exists():
            if self.split_output_dir.is_symlink():
                raise ValueError('Unsafe Gadget split output directory')
            shutil.rmtree(self.split_output_dir)
        self.split_output_dir.mkdir(parents=True)
        signed = []
        for index, split_apk in enumerate(self.split_apks):
            name = split_apk.name
            if not re.fullmatch(r'[A-Za-z0-9_.+-]+\.apk', name):
                name = f'split-{index}.apk'
            output_apk = self.split_output_dir / name
            self._sign_apk(
                split_apk,
                output_apk,
                f'Split APK {index + 1}',
            )
            signed.append(output_apk)
        return signed

    def _verify_artifact(self):
        """Verify the expected Gadget files are present."""
        _, android_abi = SUPPORTED_ABIS[self.android_abi]
        expected = {
            'AndroidManifest.xml',
            PATCH_METADATA,
            f'lib/{android_abi}/libfrida-gadget.so',
            f'lib/{android_abi}/libfrida-gadget.config.so',
            *self.network_security_resources,
        }
        if self.embedded_ca_resource:
            expected.add(self.embedded_ca_resource)
        with zipfile.ZipFile(self.output_apk) as apk:
            if not expected.issubset(apk.namelist()):
                raise RuntimeError('Signed APK is missing Frida Gadget files')

    def patch(self):
        """Build, sign, and return a Frida Gadget APK."""
        with self._patch_locks_guard:
            patch_lock = self._patch_locks.setdefault(
                self.app_dir,
                threading.Lock(),
            )
        with patch_lock:
            base_apk = self._patch()
            signed_splits = self._sign_split_apks()
            self.install_apks = [base_apk, *signed_splits]
            return base_apk

    def _patch(self):
        """Run the serialized Gadget build."""
        logger.info('Validating APK for Frida Gadget injection')
        self._validate()
        cached = self._cached_output()
        if cached:
            return cached
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
            logger.info('Writing MobSF Gadget refresh metadata')
            self._write_patch_metadata(package)
            logger.info('Rebuilding the Frida Gadget APK')
            self._build()
            logger.info(
                'Signing the Frida Gadget APK with the MobSF signing key')
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
