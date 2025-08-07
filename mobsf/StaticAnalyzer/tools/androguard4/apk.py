# -*- coding: utf_8 -*-
# flake8: noqa
# Androguard4 APK - Nov 24, 2024 - 04a5703b8ba7c181bb9f5f5995a2c16b6f9353cf
# Allows type hinting of types not-yet-declared
# in Python >= 3.7
# see https://peps.python.org/pep-0563/
from __future__ import annotations

# Python core
import binascii
import hashlib
import io
import os
import re
import unicodedata
import zipfile
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from struct import unpack
from typing import Any, Iterator, List, Tuple, Union
from xml.dom.pulldom import SAX2DOM
from zlib import crc32

import lxml.sax
from .apkinspector.headers import ZipEntry

# Used for reading Certificates
from asn1crypto import cms, keys, x509
from asn1crypto.util import OrderedDict
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa


# External dependencies
from lxml.etree import Element

# Androguard
from .axml import (
    END_DOCUMENT,
    END_TAG,
    START_TAG,
    TEXT,
    ARSCParser,
    ARSCResTableConfig,
    AXMLParser,
    AXMLPrinter,
    format_value,
)
from .util import get_certificate_name_string

import logging


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.CRITICAL)
NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree

# Dictionary of the different protection levels mapped to their corresponding attribute names as described in
# https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/content/pm/PermissionInfo.java
protection_flags_to_attributes = {
    "0x00000000": "normal",
    "0x00000001": "dangerous",
    "0x00000002": "signature",
    "0x00000003": "signature or system",
    "0x00000004": "internal",
    "0x00000010": "privileged",
    "0x00000020": "development",
    "0x00000040": "appop",
    "0x00000080": "pre23",
    "0x00000100": "installer",
    "0x00000200": "verifier",
    "0x00000400": "preinstalled",
    "0x00000800": "setup",
    "0x00001000": "instant",
    "0x00002000": "runtime only",
    "0x00004000": "oem",
    "0x00008000": "vendor privileged",
    "0x00010000": "system text classifier",
    "0x00020000": "wellbeing",
    "0x00040000": "documenter",
    "0x00080000": "configurator",
    "0x00100000": "incident report approver",
    "0x00200000": "app predictor",
    "0x00400000": "module",
    "0x00800000": "companion",
    "0x01000000": "retail demo",
    "0x02000000": "recents",
    "0x04000000": "role",
    "0x08000000": "known signer",
}


def parse_lxml_dom(tree):
    handler = SAX2DOM()
    lxml.sax.saxify(tree, handler)
    return handler.document


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class FileNotPresent(Error):
    pass


class BrokenAPKError(Error):
    pass


def _dump_additional_attributes(additional_attributes):
    """try to parse additional attributes, but ends up to hexdump if the scheme is unknown"""

    attributes_raw = io.BytesIO(additional_attributes)
    attributes_hex = binascii.hexlify(additional_attributes)

    if not len(additional_attributes):
        return attributes_hex

    (len_attribute,) = unpack('<I', attributes_raw.read(4))
    if len_attribute != 8:
        return attributes_hex

    (attr_id,) = unpack('<I', attributes_raw.read(4))
    if attr_id != APK._APK_SIG_ATTR_V2_STRIPPING_PROTECTION:
        return attributes_hex

    (scheme_id,) = unpack('<I', attributes_raw.read(4))

    return "stripping protection set, scheme %d" % scheme_id


def _dump_digests_or_signatures(digests_or_sigs):

    infos = ""
    for i, dos in enumerate(digests_or_sigs):

        infos += "\n"
        infos += " [%d]\n" % i
        infos += "  - Signature Id : %s\n" % APK._APK_SIG_ALGO_IDS.get(
            dos[0], hex(dos[0])
        )
        infos += "  - Digest: %s" % binascii.hexlify(dos[1])

    return infos


class APKV2SignedData:
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self) -> None:
        self._bytes = None
        self.digests = None
        self.certificates = None
        self.additional_attributes = None

    def __str__(self):

        certs_infos = ""

        for i, cert in enumerate(self.certificates):
            x509_cert = x509.Certificate.load(cert)

            certs_infos += "\n"
            certs_infos += " [%d]\n" % i
            certs_infos += "  - Issuer: %s\n" % get_certificate_name_string(
                x509_cert.issuer, short=True
            )
            certs_infos += "  - Subject: %s\n" % get_certificate_name_string(
                x509_cert.subject, short=True
            )
            certs_infos += "  - Serial Number: %s\n" % hex(
                x509_cert.serial_number
            )
            certs_infos += "  - Hash Algorithm: %s\n" % x509_cert.hash_algo
            certs_infos += (
                "  - Signature Algorithm: %s\n" % x509_cert.signature_algo
            )
            certs_infos += (
                "  - Valid not before: %s\n"
                % x509_cert['tbs_certificate']['validity']['not_before'].native
            )
            certs_infos += (
                "  - Valid not after: %s"
                % x509_cert['tbs_certificate']['validity']['not_after'].native
            )

        return "\n".join(
            [
                'additional_attributes : {}'.format(
                    _dump_additional_attributes(self.additional_attributes)
                ),
                'digests : {}'.format(
                    _dump_digests_or_signatures(self.digests)
                ),
                'certificates : {}'.format(certs_infos),
            ]
        )


class APKV3SignedData(APKV2SignedData):
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self) -> None:
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7FFFFFFF:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join(
            [
                'signer minSDK : {:d}'.format(self.minSDK),
                'signer maxSDK : {:s}'.format(max_sdk_str),
                base_str,
            ]
        )


class APKV2Signer:
    """
    This class holds all data associated with an APK V2 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self) -> None:
        self._bytes = None
        self.signed_data = None
        self.signatures = None
        self.public_key = None

    def __str__(self):
        return "\n".join(
            [
                '{:s}'.format(str(self.signed_data)),
                'signatures : {}'.format(
                    _dump_digests_or_signatures(self.signatures)
                ),
                'public key : {}'.format(binascii.hexlify(self.public_key)),
            ]
        )


class APKV3Signer(APKV2Signer):
    """
    This class holds all data associated with an APK V3 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self) -> None:
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7FFFFFFF:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join(
            [
                'signer minSDK : {:d}'.format(self.minSDK),
                'signer maxSDK : {:s}'.format(max_sdk_str),
                base_str,
            ]
        )


class APK:
    # Constants in ZipFile
    _PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
    _PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

    # Constants in the APK Signature Block
    _APK_SIG_MAGIC = b"APK Sig Block 42"
    _APK_SIG_KEY_V2_SIGNATURE = 0x7109871A
    _APK_SIG_KEY_V3_SIGNATURE = 0xF05368C0
    _APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xBEEFF00D

    _APK_SIG_ALGO_IDS = {
        0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        # This is for build systems which require deterministic signatures.
        0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest.",
        # This is for build systems which require deterministic signatures.
        0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest.",
        0x0201: "ECDSA with SHA2-256 digest",
        0x0202: "ECDSA with SHA2-512 digest",
        0x0301: "DSA with SHA2-256 digest",
    }

    __no_magic = False

    def __init__(
        self,
        filename: str,
        raw: bool = False,
        magic_file: Union[str, None] = None,
        skip_analysis: bool = False,
        testzip: bool = False,
    ) -> None:
        """
        This class can access to all elements in an APK file

        example::

            APK("myfile.apk")
            APK(read("myfile.apk"), raw=True)

        :param filename: specify the path of the file, or raw data
        :param raw: specify if the filename is a path or raw data (optional)
        :param magic_file: specify the magic file (not used anymore - legacy only)
        :param skip_analysis: Skip the analysis, e.g. no manifest files are read. (default: False)
        :param testzip: Test the APK for integrity, e.g. if the ZIP file is broken. Throw an exception on failure (default False)

        :type filename: string
        :type raw: boolean
        :type magic_file: string
        :type skip_analysis: boolean
        :type testzip: boolean

        """
        if magic_file:
            logger.warning(
                "You set magic_file but this parameter is actually unused. You should remove it."
            )

        self.filename = filename

        self.xml = {}
        self.axml = {}
        self.arsc = {}

        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.uses_permissions = []
        self.declared_permissions = {}
        self.valid_apk = False

        self._is_signed_v2 = None
        self._is_signed_v3 = None
        self._v2_blocks = {}
        self._v2_signing_data = None
        self._v3_signing_data = None

        self._files = {}
        self.files_crc32 = {}

        if raw is True:
            self.__raw = filename
            self._sha256 = hashlib.sha256(self.__raw).hexdigest()
            # Set the filename to something sane
            self.filename = "raw_apk_sha256:{}".format(self._sha256)
            self.zip = ZipEntry.parse(io.BytesIO(self.__raw), True)
        else:
            self.zip = ZipEntry.parse(filename, False)
            self.__raw = self.zip.zip.getvalue()

        if testzip:
            logger.info(
                "Testing zip file integrity, this might take a while..."
            )
            # Test the zipfile for integrity before continuing.
            # This process might be slow, as the whole file is read.
            # Therefore it is possible to enable it as a separate feature.
            #
            # A short benchmark showed, that testing the zip takes about 10 times longer!
            # e.g. normal zip loading (skip_analysis=True) takes about 0.01s, where
            # testzip takes 0.1s!
            test_zip = zipfile.ZipFile(io.BytesIO(self.__raw), mode="r")
            ret = test_zip.testzip()
            if ret is not None:
                # we could print the filename here, but there are zip which are so broken
                # That the filename is either very very long or does not make any sense.
                # Thus we do not do it, the user might find out by using other tools.
                raise BrokenAPKError(
                    "The APK is probably broken: testzip returned an error."
                )

        if not skip_analysis:
            self._apk_analysis()

    @staticmethod
    def _ns(name):
        """
        return the name including the Android namespace URI
        """
        return NS_ANDROID + name

    def _apk_analysis(self):
        """
        Run analysis on the APK file.

        This method is usually called by __init__ except if skip_analysis is False.
        It will then parse the AndroidManifest.xml and set all fields in the APK class which can be
        extracted from the Manifest.
        """
        i = "AndroidManifest.xml"
        logger.info("Starting analysis on {}".format(i))
        try:
            manifest_data = self.zip.read(i)
        except KeyError:
            logger.warning("Missing AndroidManifest.xml. Is this an APK file?")
        else:
            ap = AXMLPrinter(manifest_data)

            if not ap.is_valid():
                logger.error(
                    "Error while parsing AndroidManifest.xml - is the file valid?"
                )
                return

            self.axml[i] = ap
            self.xml[i] = self.axml[i].get_xml_obj()

            if self.axml[i].is_packed():
                logger.warning(
                    "XML Seems to be packed, operations on the AndroidManifest.xml might fail."
                )

            if self.xml[i] is not None:
                if self.xml[i].tag != "manifest":
                    logger.error(
                        "AndroidManifest.xml does not start with a <manifest> tag! Is this a valid APK?"
                    )
                    return

                self.package = self.get_attribute_value("manifest", "package")
                self.androidversion["Code"] = self.get_attribute_value(
                    "manifest", "versionCode"
                )
                self.androidversion["Name"] = self.get_attribute_value(
                    "manifest", "versionName"
                )
                permission = list(
                    self.get_all_attribute_value("uses-permission", "name")
                )
                self.permissions = list(set(self.permissions + permission))

                for uses_permission in self.find_tags("uses-permission"):
                    self.uses_permissions.append(
                        [
                            self.get_value_from_tag(uses_permission, "name"),
                            self._get_permission_maxsdk(uses_permission),
                        ]
                    )

                # getting details of the declared permissions
                for d_perm_item in self.find_tags('permission'):
                    d_perm_name = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "name"))
                    )
                    d_perm_label = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "label"))
                    )
                    d_perm_description = self._get_res_string_value(
                        str(
                            self.get_value_from_tag(d_perm_item, "description")
                        )
                    )
                    d_perm_permissionGroup = self._get_res_string_value(
                        str(
                            self.get_value_from_tag(
                                d_perm_item, "permissionGroup"
                            )
                        )
                    )
                    d_perm_protectionLevel = self._get_res_string_value(
                        str(
                            self.get_value_from_tag(
                                d_perm_item, "protectionLevel"
                            )
                        )
                    )

                    d_perm_details = {
                        "label": d_perm_label,
                        "description": d_perm_description,
                        "permissionGroup": d_perm_permissionGroup,
                        "protectionLevel": d_perm_protectionLevel,
                    }
                    self.declared_permissions[d_perm_name] = d_perm_details

                self.valid_apk = True
                logger.info("APK file was successfully validated!")

        # self.permission_module = androconf.load_api_specific_resource_module(
        #     "aosp_permissions", self.get_target_sdk_version()
        # )
        # self.permission_module_min_sdk = (
        #     androconf.load_api_specific_resource_module(
        #         "aosp_permissions", self.get_min_sdk_version()
        #     )
        # )

    def __getstate__(self):
        """
        Function for pickling APK Objects.

        We remove the zip from the Object, as it is not pickable
        And it does not make any sense to pickle it anyways.

        :returns: the picklable APK Object without zip.
        """
        # Upon pickling, we need to remove the ZipFile
        x = self.__dict__
        x['axml'] = str(x['axml'])
        x['xml'] = str(x['xml'])
        del x['zip']

        return x

    def __setstate__(self, state):
        """
        Load a pickled APK Object and restore the state

        We load the zip file back by reading __raw from the Object.

        :param state: pickled state
        """
        self.__dict__ = state

        self.zip = zipfile.ZipFile(io.BytesIO(self.get_raw()), mode="r")

    def _get_res_string_value(self, string):
        if not string.startswith('@string/'):
            return string
        string_key = string[9:]

        res_parser = self.get_android_resources()
        if not res_parser:
            return ''
        string_value = ''
        for package_name in res_parser.get_packages_names():
            extracted_values = res_parser.get_string(package_name, string_key)
            if extracted_values:
                string_value = extracted_values[1]
                break
        return string_value

    def _get_permission_maxsdk(self, item):
        maxSdkVersion = None
        try:
            maxSdkVersion = int(self.get_value_from_tag(item, "maxSdkVersion"))
        except ValueError:
            logger.warning(
                str(maxSdkVersion)
                + ' is not a valid value for <uses-permission> maxSdkVersion'
            )
        except TypeError:
            pass
        return maxSdkVersion

    def is_valid_APK(self) -> bool:
        """
        Return true if the APK is valid, false otherwise.
        An APK is seen as valid, if the AndroidManifest.xml could be successful parsed.
        This does not mean that the APK has a valid signature nor that the APK
        can be installed on an Android system.

        :rtype: boolean
        """
        return self.valid_apk

    def get_filename(self) -> str:
        """
        Return the filename of the APK

        :rtype: :class:`str`
        """
        return self.filename

    def get_app_name(self, locale=None) -> str:
        """
        Return the appname of the APK

        This name is read from the AndroidManifest.xml
        using the application android:label.
        If no label exists, the android:label of the main activity is used.

        If there is also no main activity label, an empty string is returned.

        :rtype: :class:`str`
        """

        app_name = self.get_attribute_value('application', 'label')
        if app_name is None:
            activities = self.get_main_activities()
            main_activity_name = None
            if len(activities) > 0:
                main_activity_name = activities.pop()

            # FIXME: would need to use _format_value inside get_attribute_value for each returned name!
            # For example, as the activity name might be foobar.foo.bar but inside the activity it is only .bar
            app_name = self.get_attribute_value(
                'activity', 'label', name=main_activity_name
            )

        if app_name is None:
            # No App name set
            # TODO return packagename instead?
            logger.warning(
                "It looks like that no app name is set for the main activity!"
            )
            return ""

        if app_name.startswith("@"):
            res_parser = self.get_android_resources()
            if not res_parser:
                # TODO: What should be the correct return value here?
                return app_name

            res_id, package = res_parser.parse_id(app_name)

            # If the package name is the same as the APK package,
            # we should be able to resolve the ID.
            if package and package != self.get_package():
                if package == 'android':
                    # TODO: we can not resolve this, as we lack framework-res.apk
                    # one exception would be when parsing framework-res.apk directly.
                    logger.warning(
                        "Resource ID with android package name encountered! "
                        "Will not resolve, framework-res.apk would be required."
                    )
                    return app_name
                else:
                    # TODO should look this up, might be in the resources
                    logger.warning(
                        "Resource ID with Package name '{}' encountered! Will not resolve".format(
                            package
                        )
                    )
                    return app_name

            try:
                config = (
                    ARSCResTableConfig(None, locale=locale)
                    if locale
                    else ARSCResTableConfig.default_config()
                )
                app_name = res_parser.get_resolved_res_configs(res_id, config)[
                    0
                ][1]
            except Exception as e:
                logger.warning("Exception selecting app name: %s" % e)
        return app_name

    def get_app_icon(self, max_dpi: int = 65536) -> Union[str, None]:
        """
        Return the first icon file name, which density is not greater than max_dpi,
        unless exact icon resolution is set in the manifest, in which case
        return the exact file.

        This information is read from the AndroidManifest.xml

        From https://developer.android.com/guide/practices/screens_support.html
        and https://developer.android.com/ndk/reference/group___configuration.html

        * DEFAULT                             0dpi
        * ldpi (low)                        120dpi
        * mdpi (medium)                     160dpi
        * TV                                213dpi
        * hdpi (high)                       240dpi
        * xhdpi (extra-high)                320dpi
        * xxhdpi (extra-extra-high)         480dpi
        * xxxhdpi (extra-extra-extra-high)  640dpi
        * anydpi                          65534dpi (0xFFFE)
        * nodpi                           65535dpi (0xFFFF)

        There is a difference between nodpi and anydpi:
        nodpi will be used if no other density is specified. Or the density does not match.
        nodpi is the fallback for everything else. If there is a resource that matches the DPI,
        this is used.
        anydpi is also valid for all densities but in this case, anydpi will overrule all other files!
        Therefore anydpi is usually used with vector graphics and with constraints on the API level.
        For example adaptive icons are usually marked as anydpi.

        When it comes now to selecting an icon, there is the following flow:

        1. is there an anydpi icon?
        2. is there an icon for the dpi of the device?
        3. is there a nodpi icon?
        4. (only on very old devices) is there a icon with dpi 0 (the default)

        For more information read here: https://stackoverflow.com/a/34370735/446140

        :rtype: :class:`str`
        """
        main_activity_name = self.get_main_activity()

        app_icon = self.get_attribute_value(
            'activity', 'icon', name=main_activity_name
        )

        if not app_icon:
            app_icon = self.get_attribute_value('application', 'icon')

        res_parser = self.get_android_resources()
        if not res_parser:
            # Can not do anything below this point to resolve...
            return None

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(
                self.package, 'mipmap', 'ic_launcher'
            )
            if res_id:
                app_icon = "@%x" % res_id

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(
                self.package, 'drawable', 'ic_launcher'
            )
            if res_id:
                app_icon = "@%x" % res_id

        if not app_icon:
            # If the icon can not be found, return now
            return None

        if app_icon.startswith("@"):
            app_icon_id = app_icon[1:]
            app_icon_id = app_icon_id.split(':')[-1]
            res_id = int(app_icon_id, 16)
            candidates = res_parser.get_resolved_res_configs(res_id)

            app_icon = None
            current_dpi = -1

            try:
                for config, file_name in candidates:
                    dpi = config.get_density()
                    if current_dpi < dpi <= max_dpi:
                        app_icon = file_name
                        current_dpi = dpi
            except Exception as e:
                logger.warning("Exception selecting app icon: %s" % e)

        return app_icon

    def get_package(self) -> str:
        """
        Return the name of the package

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.package

    def get_androidversion_code(self) -> str:
        """
        Return the android version code

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self) -> str:
        """
        Return the android version name

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Name"]

    def get_files(self) -> list[str]:
        """
        Return the file names inside the APK.

        :rtype: a list of :class:`str`
        """
        return self.zip.namelist()

    # def _get_file_magic_name(self, buffer: bytes) -> str:
    #     """
    #     Return the filetype guessed for a buffer
    #     :param buffer: bytes
    #     :returns: str of filetype
    #     """
    #     default = "Unknown"

    #     # Faster way, test once, return default.
    #     if self.__no_magic:
    #         return default

    #     try:
    #         # Magic is optional
    #         import magic
    #     except ImportError:
    #         self.__no_magic = True
    #         logger.warning("No Magic library was found on your system.")
    #         return default
    #     except TypeError as e:
    #         self.__no_magic = True
    #         logger.warning(
    #             "It looks like you have the magic python package installed but not the magic library itself!"
    #         )
    #         logger.warning("Error from magic library: %s", e)
    #         logger.warning(
    #             "Please follow the installation instructions at https://github.com/ahupp/python-magic/#installation"
    #         )
    #         logger.warning(
    #             "You can also install the 'python-magic-bin' package on Windows and MacOS"
    #         )
    #         return default

    #     try:
    #         # There are several implementations of magic,
    #         # unfortunately all called magic
    #         # We use this one: https://github.com/ahupp/python-magic/
    #         # You can also use python-magic-bin on Windows or MacOS
    #         getattr(magic, "MagicException")
    #     except AttributeError:
    #         self.__no_magic = True
    #         logger.warning(
    #             "Not the correct Magic library was found on your "
    #             "system. Please install python-magic or python-magic-bin!"
    #         )
    #         return default

    #     try:
    #         # 1024 byte are usually enough to test the magic
    #         ftype = magic.from_buffer(buffer[:1024])
    #     except magic.MagicException as e:
    #         logger.exception("Error getting the magic type: %s", e)
    #         return default

    #     if not ftype:
    #         return default
    #     else:
    #         return self._patch_magic(buffer, ftype)

    # @property
    # def files(self) -> dict[str, str]:
    #     """
    #     Returns a dictionary of filenames and detected magic type

    #     :returns: dictionary of files and their mime type
    #     """
    #     return self.get_files_types()

    # def get_files_types(self) -> dict[str, str]:
    #     """
    #     Return the files inside the APK with their associated types (by using python-magic)

    #     At the same time, the CRC32 are calculated for the files.

    #     :rtype: a dictionary
    #     """
    #     if self._files == {}:
    #         # Generate File Types / CRC List
    #         for i in self.get_files():
    #             buffer = self._get_crc32(i)
    #             self._files[i] = self._get_file_magic_name(buffer)

    #     return self._files

    # def _patch_magic(self, buffer, orig):
    #     """
    #     Overwrite some probably wrong detections by mime libraries

    #     :param buffer: bytes of the file to detect
    #     :param orig: guess by mime libary
    #     :returns: corrected guess
    #     """
    #     if (
    #         ("Zip" in orig)
    #         or ('(JAR)' in orig)
    #         and androconf.is_android_raw(buffer) == 'APK'
    #     ):
    #         return "Android application package file"

    #     return orig

    def _get_crc32(self, filename):
        """
        Calculates and compares the CRC32 and returns the raw buffer.

        The CRC32 is added to `files_crc32` dictionary, if not present.

        :param filename: filename inside the zipfile
        :rtype: bytes
        """
        buffer = self.zip.read(filename)
        if filename not in self.files_crc32:
            self.files_crc32[filename] = crc32(buffer)
            if (
                self.files_crc32[filename]
                != self.zip.infolist()[filename].crc32_of_uncompressed_data
            ):
                logger.error(
                    "File '{}' has different CRC32 after unpacking! "
                    "Declared: {:08x}, Calculated: {:08x}".format(
                        filename,
                        self.zip.infolist()[
                            filename
                        ].crc32_of_uncompressed_data,
                        self.files_crc32[filename],
                    )
                )
        return buffer

    def get_files_crc32(self) -> dict[str, int]:
        """
        Calculates and returns a dictionary of filenames and CRC32

        :returns: dict of filename: CRC32
        """
        if self.files_crc32 == {}:
            for i in self.get_files():
                self._get_crc32(i)

        return self.files_crc32

    def get_files_information(self) -> Iterator[tuple[str, str, int]]:
        """
        Return the files inside the APK with their associated types and crc32

        :rtype: str, str, int
        """
        for k in self.get_files():
            yield k, self.get_files_types()[k], self.get_files_crc32()[k]

    def get_raw(self) -> bytes:
        """
        Return raw bytes of the APK

        :rtype: bytes
        """

        if self.__raw:
            return self.__raw
        else:
            with open(self.filename, 'rb') as f:
                self.__raw = bytearray(f.read())
            return self.__raw

    def get_file(self, filename: str) -> bytes:
        """
        Return the raw data of the specified filename
        inside the APK

        :rtype: bytes
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self) -> bytes:
        """
        Return the raw data of the classes dex file

        This will give you the data of the file called `classes.dex`
        inside the APK. If the APK has multiple DEX files, you need to use :func:`~APK.get_all_dex`.

        :rtype: bytes
        """
        try:
            return self.get_file("classes.dex")
        except FileNotPresent:
            # TODO is this a good idea to return an empty string?
            return b""

    def get_dex_names(self) -> list[str]:
        """
        Return the names of all DEX files found in the APK.
        This method only accounts for "offical" dex files, i.e. all files
        in the root directory of the APK named classes.dex or classes[0-9]+.dex

        :rtype: a list of str
        """
        dexre = re.compile(r"^classes(\d*).dex$")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self) -> Iterator[bytes]:
        """
        Return the raw data of all classes dex files

        :rtype: a generator of bytes
        """
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def is_multidex(self) -> bool:
        """
        Test if the APK has multiple DEX files

        :returns: True if multiple dex found, otherwise False
        """
        dexre = re.compile(r"^classes(\d+)?.dex$")
        return (
            len(
                [
                    instance
                    for instance in self.get_files()
                    if dexre.search(instance)
                ]
            )
            > 1
        )

    def _format_value(self, value):
        """
        Format a value with packagename, if not already set.
        For example, the name :code:`'.foobar'` will be transformed into :code:`'package.name.foobar'`.

        Names which do not contain any dots are assumed to be packagename-less as well:
        :code:`foobar` will also transform into :code:`package.name.foobar`.

        :param value:
        :returns:
        """
        if value and self.package:
            v_dot = value.find(".")
            if v_dot == 0:
                # Dot at the start
                value = self.package + value
            elif v_dot == -1:
                # Not a single dot
                value = self.package + "." + value
        return value

    def get_all_attribute_value(
        self,
        tag_name: str,
        attribute: str,
        format_value: bool = True,
        **attribute_filter,
    ) -> Iterator[str]:
        """
        Yields all the attribute values in xml files which match with the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """
        tags = self.find_tags(tag_name, **attribute_filter)
        for tag in tags:
            value = tag.get(self._ns(attribute)) or tag.get(attribute)
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value

    def get_attribute_value(
        self,
        tag_name: str,
        attribute: str,
        format_value: bool = False,
        **attribute_filter,
    ) -> str:
        """
        Return the attribute value in xml files which matches the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """

        for value in self.get_all_attribute_value(
            tag_name, attribute, format_value, **attribute_filter
        ):
            if value is not None:
                return value

    def get_value_from_tag(
        self, tag: Element, attribute: str
    ) -> Union[str, None]:
        """
        Return the value of the android prefixed attribute in a specific tag.

        This function will always try to get the attribute with a android: prefix first,
        and will try to return the attribute without the prefix, if the attribute could not be found.
        This is useful for some broken AndroidManifest.xml, where no android namespace is set,
        but could also indicate malicious activity (i.e. wrongly repackaged files).
        A warning is printed if the attribute is found without a namespace prefix.

        If you require to get the exact result you need to query the tag directly:

        example::
            >>> from lxml.etree import Element
            >>> tag = Element('bar', nsmap={'android': 'http://schemas.android.com/apk/res/android'})
            >>> tag.set('{http://schemas.android.com/apk/res/android}foobar', 'barfoo')
            >>> tag.set('name', 'baz')
            # Assume that `a` is some APK object
            >>> a.get_value_from_tag(tag, 'name')
            'baz'
            >>> tag.get('name')
            'baz'
            >>> tag.get('foobar')
            None
            >>> a.get_value_from_tag(tag, 'foobar')
            'barfoo'

        :param lxml.etree.Element tag: specify the tag element
        :param str attribute: specify the attribute name
        :returns: the attribute's value, or None if the attribute is not present
        """

        # TODO: figure out if both android:name and name tag exist which one to give preference:
        # currently we give preference for the namespace one and fallback to the un-namespaced
        value = tag.get(self._ns(attribute))
        if value is None:
            value = tag.get(attribute)

            if value:
                # If value is still None, the attribute could not be found, thus is not present
                logger.warning(
                    "Failed to get the attribute '{}' on tag '{}' with namespace. "
                    "But found the same attribute without namespace!".format(
                        attribute, tag.tag
                    )
                )
        return value

    def find_tags(self, tag_name: str, **attribute_filter) -> list[str]:
        """
        Return a list of all the matched tags in all available xml

        :param str tag: specify the tag name
        """
        all_tags = [
            self.find_tags_from_xml(i, tag_name, **attribute_filter)
            for i in self.xml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tags_from_xml(
        self, xml_name: str, tag_name: str, **attribute_filter
    ) -> list[str]:
        """
        Return a list of all the matched tags in a specific xml
        w
        :param str xml_name: specify from which xml to pick the tag from
        :param str tag_name: specify the tag name
        """
        xml = self.xml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(xml.tag, **attribute_filter):
                return [xml]
            return []
        tags = set()
        tags.update(xml.findall(".//" + tag_name))

        # https://github.com/androguard/androguard/pull/1053
        # permission declared using tag <android:uses-permission...
        tags.update(xml.findall(".//" + NS_ANDROID + tag_name))
        return [
            tag for tag in tags if self.is_tag_matched(tag, **attribute_filter)
        ]

    def is_tag_matched(self, tag: str, **attribute_filter) -> bool:
        r"""
        Return true if the attributes matches in attribute filter.

        An attribute filter is a dictionary containing: {attribute_name: value}.
        This function will return True if and only if all attributes have the same value.
        This function allows to set the dictionary via kwargs, thus you can filter like this:

        example::
            a.is_tag_matched(tag, name="foobar", other="barfoo")

        This function uses a fallback for attribute searching. It will by default use
        the namespace variant but fall back to the non-namespace variant.
        Thus specifiying :code:`{"name": "foobar"}` will match on :code:`<bla name="foobar" \>`
        as well as on :code:`<bla android:name="foobar" \>`.

        :param lxml.etree.Element tag: specify the tag element
        :param attribute_filter: specify the attribute filter as dictionary
        """
        if len(attribute_filter) <= 0:
            return True
        for attr, value in attribute_filter.items():
            _value = self.get_value_from_tag(tag, attr)
            if _value != value:
                return False
        return True

    def get_main_activities(self) -> set[str]:
        """
        Return names of the main activities

        These values are read from the AndroidManifest.xml

        :rtype: a set of str
        """
        x = set()
        y = set()

        for i in self.xml:
            if self.xml[i] is None:
                continue
            activities_and_aliases = self.xml[i].findall(
                ".//activity"
            ) + self.xml[i].findall(".//activity-alias")

            for item in activities_and_aliases:
                # Some applications have more than one MAIN activity.
                # For example: paid and free content
                activityEnabled = item.get(self._ns("enabled"))
                if activityEnabled == "false":
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.action.MAIN":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            x.add(item.get(self._ns("name")))
                        else:
                            logger.warning('Main activity without name')

                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            y.add(item.get(self._ns("name")))
                        else:
                            logger.warning('Launcher activity without name')

        return x.intersection(y)

    def get_main_activity(self) -> Union[str, None]:
        """
        Return the name of the main activity

        This value is read from the AndroidManifest.xml

        :rtype: str
        """
        activities = self.get_main_activities()
        if len(activities) == 1:
            return self._format_value(activities.pop())
        elif len(activities) > 1:
            main_activities = {self._format_value(ma) for ma in activities}
            # sorted is necessary
            # 9fc7d3e8225f6b377f9181a92c551814317b77e1aa0df4c6d508d24b18f0f633
            good_main_activities = sorted(
                main_activities.intersection(self.get_activities())
            )
            if good_main_activities:
                return good_main_activities[0]
            return sorted(main_activities)[0]
        return None

    def get_activities(self) -> list[str]:
        """
        Return the android:name attribute of all activities

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("activity", "name"))

    def get_activity_aliases(self) -> list[dict[str, str]]:
        """
        Return the android:name and android:targetActivity attribute of all activity aliases.

        :rtype: a list of dict
        """
        ali = []
        for alias in self.find_tags('activity-alias'):
            activity_alias = {}
            for attribute in ['name', 'targetActivity']:
                value = alias.get(attribute) or alias.get(self._ns(attribute))
                if not value:
                    continue
                activity_alias[attribute] = self._format_value(value)
            if activity_alias:
                ali.append(activity_alias)
        return ali

    def get_services(self) -> list[str]:
        """
        Return the android:name attribute of all services

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("service", "name"))

    def get_receivers(self) -> list[str]:
        """
        Return the android:name attribute of all receivers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("receiver", "name"))

    def get_providers(self) -> list[str]:
        """
        Return the android:name attribute of all providers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("provider", "name"))

    def get_res_value(self, name: str) -> str:
        """
        Return the literal value with a resource id
        :rtype: str
        """

        res_parser = self.get_android_resources()
        if not res_parser:
            return name

        res_id = res_parser.parse_id(name)[0]
        try:
            value = res_parser.get_resolved_res_configs(
                res_id, ARSCResTableConfig.default_config()
            )[0][1]
        except Exception as e:
            logger.warning("Exception get resolved resource id: %s" % e)
            return name

        return value

    def get_intent_filters(
        self, itemtype: str, name: str
    ) -> dict[str, list[str]]:
        """
        Find intent filters for a given item and name.

        Intent filter are attached to activities, services or receivers.
        You can search for the intent filters of such items and get a dictionary of all
        attached actions and intent categories.

        :param itemtype: the type of parent item to look for, e.g. `activity`,  `service` or `receiver`
        :param name: the `android:name` of the parent item, e.g. activity name
        :returns: a dictionary with the keys `action` and `category` containing the `android:name` of those items
        """
        attributes = {
            "action": ["name"],
            "category": ["name"],
            "data": [
                'scheme',
                'host',
                'port',
                'path',
                'pathPattern',
                'pathPrefix',
                'mimeType',
            ],
        }

        d = {}
        for element in attributes.keys():
            d[element] = []

        for i in self.xml:
            # TODO: this can probably be solved using a single xpath
            for item in self.xml[i].findall(".//" + itemtype):
                if self._format_value(item.get(self._ns("name"))) == name:
                    for sitem in item.findall(".//intent-filter"):
                        for element in d.keys():
                            for ssitem in sitem.findall(element):
                                if element == 'data':  # multiple attributes
                                    values = {}
                                    for attribute in attributes[element]:
                                        value = ssitem.get(self._ns(attribute))
                                        if value:
                                            if value.startswith('@'):
                                                value = self.get_res_value(
                                                    value
                                                )
                                            values[attribute] = value

                                    if values:
                                        d[element].append(values)
                                else:
                                    for attribute in attributes[element]:
                                        value = ssitem.get(self._ns(attribute))
                                        if value.startswith('@'):
                                            value = self.get_res_value(value)

                                        if value not in d[element]:
                                            d[element].append(value)

        for element in list(d.keys()):
            if not d[element]:
                del d[element]

        return d

    def get_permissions(self) -> list[str]:
        """
        Return permissions names declared in the AndroidManifest.xml.

        It is possible that permissions are returned multiple times,
        as this function does not filter the permissions, i.e. it shows you
        exactly what was defined in the AndroidManifest.xml.

        Implied permissions, which are granted automatically, are not returned
        here. Use :meth:`get_uses_implied_permission_list` if you need a list
        of implied permissions.

        :returns: A list of permissions
        :rtype: list
        """
        return self.permissions

    def get_uses_implied_permission_list(self) -> list[str]:
        """
        Return all permissions implied by the target SDK or other permissions.

        :rtype: list of string
        """
        target_sdk_version = self.get_effective_target_sdk_version()

        READ_CALL_LOG = 'android.permission.READ_CALL_LOG'
        READ_CONTACTS = 'android.permission.READ_CONTACTS'
        READ_EXTERNAL_STORAGE = 'android.permission.READ_EXTERNAL_STORAGE'
        READ_PHONE_STATE = 'android.permission.READ_PHONE_STATE'
        WRITE_CALL_LOG = 'android.permission.WRITE_CALL_LOG'
        WRITE_CONTACTS = 'android.permission.WRITE_CONTACTS'
        WRITE_EXTERNAL_STORAGE = 'android.permission.WRITE_EXTERNAL_STORAGE'

        implied = []

        implied_WRITE_EXTERNAL_STORAGE = False
        if target_sdk_version < 4:
            if WRITE_EXTERNAL_STORAGE not in self.permissions:
                implied.append([WRITE_EXTERNAL_STORAGE, None])
                implied_WRITE_EXTERNAL_STORAGE = True
            if READ_PHONE_STATE not in self.permissions:
                implied.append([READ_PHONE_STATE, None])

        if (
            WRITE_EXTERNAL_STORAGE in self.permissions
            or implied_WRITE_EXTERNAL_STORAGE
        ) and READ_EXTERNAL_STORAGE not in self.permissions:
            maxSdkVersion = None
            for name, version in self.uses_permissions:
                if name == WRITE_EXTERNAL_STORAGE:
                    maxSdkVersion = version
                    break
            implied.append([READ_EXTERNAL_STORAGE, maxSdkVersion])

        if target_sdk_version < 16:
            if (
                READ_CONTACTS in self.permissions
                and READ_CALL_LOG not in self.permissions
            ):
                implied.append([READ_CALL_LOG, None])
            if (
                WRITE_CONTACTS in self.permissions
                and WRITE_CALL_LOG not in self.permissions
            ):
                implied.append([WRITE_CALL_LOG, None])

        return implied

    def _update_permission_protection_level(
        self, protection_level, sdk_version
    ):
        if not sdk_version or int(sdk_version) <= 15:
            return protection_level.replace('Or', '|').lower()
        return protection_level

    def _fill_deprecated_permissions(self, permissions):
        min_sdk = self.get_min_sdk_version()
        target_sdk = self.get_target_sdk_version()
        filled_permissions = permissions.copy()
        for permission in filled_permissions:
            protection_level, label, description = filled_permissions[
                permission
            ]
            if (
                not label or not description
            ) and permission in self.permission_module_min_sdk:
                x = self.permission_module_min_sdk[permission]
                protection_level = self._update_permission_protection_level(
                    x['protectionLevel'], min_sdk
                )
                filled_permissions[permission] = [
                    protection_level,
                    x['label'],
                    x['description'],
                ]
            else:
                filled_permissions[permission] = [
                    self._update_permission_protection_level(
                        protection_level, target_sdk
                    ),
                    label,
                    description,
                ]
        return filled_permissions

    def get_details_permissions(self) -> dict[str, list[str]]:
        """
        Return permissions with details.

        THis can only return details about the permission, if the permission is
        defined in the AOSP.

        :rtype: dict of {permission: [protectionLevel, label, description]}
        """
        l = {}

        for i in self.permissions:
            if i in self.permission_module:
                x = self.permission_module[i]
                l[i] = [x["protectionLevel"], x["label"], x["description"]]
            elif i in self.declared_permissions:
                protectionLevel_hex = self.declared_permissions[i][
                    "protectionLevel"
                ]
                protectionLevel = protection_flags_to_attributes[
                    protectionLevel_hex
                ]
                l[i] = [
                    protectionLevel,
                    "Unknown permission from android reference",
                    "Unknown permission from android reference",
                ]
            else:
                # Is there a valid case not belonging to the above two?
                logger.info(f"Unknown permission {i}")
        return self._fill_deprecated_permissions(l)

    def get_requested_aosp_permissions(self) -> list[str]:
        """
        Returns requested permissions declared within AOSP project.

        This includes several other permissions as well, which are in the platform apps.

        :rtype: list of str
        """
        aosp_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm in list(self.permission_module.keys()):
                aosp_permissions.append(perm)
        return aosp_permissions

    def get_requested_aosp_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns requested aosp permissions with details.

        :rtype: dictionary
        """
        l = {}
        for i in self.permissions:
            try:
                l[i] = self.permission_module[i]
            except KeyError:
                # if we have not found permission do nothing
                continue
        return l

    def get_requested_third_party_permissions(self) -> list[str]:
        """
        Returns list of requested permissions not declared within AOSP project.

        :rtype: list of strings
        """
        third_party_permissions = []
        all_permissions = self.get_permissions()
        for perm in all_permissions:
            if perm not in list(self.permission_module.keys()):
                third_party_permissions.append(perm)
        return third_party_permissions

    def get_declared_permissions(self) -> list[str]:
        """
        Returns list of the declared permissions.

        :rtype: list of strings
        """
        return list(self.declared_permissions.keys())

    def get_declared_permissions_details(self) -> dict[str, list[str]]:
        """
        Returns declared permissions with the details.

        :rtype: dict
        """
        return self.declared_permissions

    def get_max_sdk_version(self) -> str:
        """
        Return the android:maxSdkVersion attribute

        :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "maxSdkVersion")

    def get_min_sdk_version(self) -> str:
        """
        Return the android:minSdkVersion attribute

        :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "minSdkVersion")

    def get_target_sdk_version(self) -> str:
        """
        Return the android:targetSdkVersion attribute

        :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "targetSdkVersion")

    def get_effective_target_sdk_version(self) -> int:
        """
        Return the effective targetSdkVersion, always returns int > 0.

        If the targetSdkVersion is not set, it defaults to 1.  This is
        set based on defaults as defined in:
        https://developer.android.com/guide/topics/manifest/uses-sdk-element.html

        :rtype: int
        """
        target_sdk_version = self.get_target_sdk_version()
        if not target_sdk_version:
            target_sdk_version = self.get_min_sdk_version()
        try:
            return int(target_sdk_version)
        except (ValueError, TypeError):
            return 1

    def get_libraries(self) -> list[str]:
        """
        Return the android:name attributes for libraries

        :rtype: list
        """
        return list(self.get_all_attribute_value("uses-library", "name"))

    def get_features(self) -> list[str]:
        """
        Return a list of all android:names found for the tag uses-feature
        in the AndroidManifest.xml

        :returns: list
        """
        return list(self.get_all_attribute_value("uses-feature", "name"))

    def is_wearable(self) -> bool:
        """
        Checks if this application is build for wearables by
        checking if it uses the feature 'android.hardware.type.watch'
        See: https://developer.android.com/training/wearables/apps/creating.html for more information.

        Not every app is setting this feature (not even the example Google provides),
        so it might be wise to not 100% rely on this feature.

        :returns: True if wearable, False otherwise
        """
        return 'android.hardware.type.watch' in self.get_features()

    def is_leanback(self) -> bool:
        """
        Checks if this application is build for TV (Leanback support)
        by checkin if it uses the feature 'android.software.leanback'

        :returns: True if leanback feature is used, false otherwise
        """
        return 'android.software.leanback' in self.get_features()

    def is_androidtv(self) -> bool:
        """
        Checks if this application does not require a touchscreen,
        as this is the rule to get into the TV section of the Play Store
        See: https://developer.android.com/training/tv/start/start.html for more information.

        :returns: True if 'android.hardware.touchscreen' is not required, False otherwise
        """
        return (
            self.get_attribute_value(
                'uses-feature',
                'name',
                required="false",
                name="android.hardware.touchscreen",
            )
            == "android.hardware.touchscreen"
        )

    def get_certificate_der(
        self, filename: str, max_sdk_version: int = None
    ) -> Union[bytes, None]:
        """
        Return the DER coded X.509 certificate from the signature file.
        If minSdkVersion is prior to Android N only the first SignerInfo is used.
        If signed attributes are present, they are taken into account
        Note that unsupported critical extensions and key usage are not verified!
        https://android.googlesource.com/platform/tools/apksig/+/refs/tags/platform-tools-34.0.5/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java#668

        :param filename: Signature filename in APK
        :param max_sdk_version: An optional integer parameter for the max sdk version
        :returns: DER coded X.509 certificate as binary or None
        """

        # Get the signature
        pkcs7message = self.get_file(filename)
        # Get the .SF
        sf_filename = os.path.splitext(filename)[0] + '.SF'
        sf_object = self.get_file(sf_filename)
        # Load the signature
        signed_data = cms.ContentInfo.load(pkcs7message)
        # Locate the SignerInfo structure
        signer_infos = signed_data['content']['signer_infos']
        if not signer_infos:
            logger.error(
                'No signer information found in the PKCS7 object. The APK may not be properly signed.'
            )
            return None

        # Prior to Android N, Android attempts to verify only the first SignerInfo. From N onwards, Android attempts
        # to verify all SignerInfos and then picks the first verified SignerInfo.
        min_sdk_version = self.get_min_sdk_version()
        if (
            min_sdk_version is None or int(min_sdk_version) < 24
        ):  # AndroidSdkVersion.N
            logger.info(
                f"minSdkVersion: {min_sdk_version} is less than 24. Getting the first signerInfo only!"
            )
            unverified_signer_infos_to_try = [signer_infos[0]]
        else:
            unverified_signer_infos_to_try = signer_infos

        # Extract certificates from the PKCS7 object
        certificates = signed_data['content']['certificates']
        return_certificate = None
        list_certificates_verified = []
        for signer_info in unverified_signer_infos_to_try:
            try:
                matching_certificate_verified = (
                    self.verify_signer_info_against_sig_file(
                        signed_data,
                        certificates,
                        signer_info,
                        sf_object,
                        max_sdk_version,
                    )
                )
            except (ValueError, TypeError, OSError, InvalidSignature) as e:
                logger.error(
                    f"The following exception was raised while verifying the certificate: {e}"
                )
                return (
                    None  # the validation stops due to the exception raised!
                )
            if matching_certificate_verified is not None:
                list_certificates_verified.append(
                    matching_certificate_verified
                )
        if not list_certificates_verified:
            logger.error(
                f"minSdkVersion: {min_sdk_version}, # of SignerInfos: {len(unverified_signer_infos_to_try)}. None Verified!"
            )
        else:
            return_certificate = list_certificates_verified[0]
        return return_certificate

    def verify_signer_info_against_sig_file(
        self,
        signed_data,
        certificates,
        signer_info,
        sf_object,
        max_sdk_version,
    ):
        matching_certificate = self.find_certificate(certificates, signer_info)
        matching_certificate_verified = None
        digest_algorithm, crypto_hash_algorithm = self.get_hash_algorithm(
            signer_info
        )
        if matching_certificate is None:
            raise ValueError(
                "Signing certificate referenced in SignerInfo not found in SignedData"
            )
        else:
            if signer_info['signed_attrs'].native:
                logger.info("Signed Attributes detected!")
                signed_attrs = signer_info['signed_attrs']
                signed_attrs_dict = OrderedDict()
                for attr in signed_attrs:
                    if attr['type'].dotted in signed_attrs_dict:
                        raise ValueError(
                            f"Duplicate signed attribute: {attr['type'].dotted}"
                        )
                    signed_attrs_dict[attr['type'].dotted] = attr['values']

                # Check content type attribute (for Android N and newer)
                if max_sdk_version is None or int(max_sdk_version) >= 24:
                    content_type_oid = (
                        '1.2.840.113549.1.9.3'  # OID for contentType
                    )
                    if content_type_oid not in signed_attrs_dict:
                        raise ValueError(
                            "No Content Type in signed attributes"
                        )
                    content_type = signed_attrs_dict[content_type_oid][
                        0
                    ].native
                    if (
                        content_type
                        != signed_data['content']['encap_content_info'][
                            'content_type'
                        ].native
                    ):
                        logger.error(
                            "Content Type mismatch. Continuing to next SignerInfo, if any."
                        )
                        return None

                # Check message digest attribute
                message_digest_oid = (
                    '1.2.840.113549.1.9.4'  # OID for messageDigest
                )
                if message_digest_oid not in signed_attrs_dict:
                    raise ValueError("No content digest in signed attributes")
                expected_signature_file_digest = signed_attrs_dict[
                    message_digest_oid
                ][0].native
                hash_algo = digest_algorithm()
                hash_algo.update(sf_object)
                actual_digest = hash_algo.digest()

                # Compare digests
                if actual_digest != expected_signature_file_digest:
                    logger.error(
                        "Digest mismatch. Continuing to next SignerInfo, if any."
                    )
                    return None

                signed_attrs_dump = signed_attrs.dump()
                # Modify the first byte to 0x31 for UNIVERSAL SET
                signed_attrs_dump = b'\x31' + signed_attrs_dump[1:]
                matching_certificate_verified = self.verify_signature(
                    signer_info,
                    matching_certificate,
                    signed_attrs_dump,
                    crypto_hash_algorithm,
                )
            else:
                matching_certificate_verified = self.verify_signature(
                    signer_info,
                    matching_certificate,
                    sf_object,
                    crypto_hash_algorithm,
                )
        return matching_certificate_verified

    @staticmethod
    def verify_signature(
        signer_info, matching_certificate, signed_data, crypto_hash_algorithm
    ):
        matching_certificate_verified = None
        signature = signer_info['signature'].native

        # Load the certificate using asn1crypto as it can handle more cases (v1-only-with-rsa-1024-cert-not-der.apk)
        cert = x509.Certificate.load(matching_certificate.chosen.dump())
        public_key_info = cert.public_key

        # Convert the ASN.1 public key to a cryptography-compatible object
        public_key_der = public_key_info.dump()
        public_key = serialization.load_der_public_key(
            public_key_der, backend=default_backend()
        )

        try:
            # RSA Key
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    signed_data,
                    padding.PKCS1v15(),
                    crypto_hash_algorithm(),
                )

            # DSA Key
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature, signed_data, crypto_hash_algorithm()
                )

            # EC Key
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature, signed_data, ec.ECDSA(crypto_hash_algorithm())
                )

            else:
                raise ValueError(
                    f"Unsupported key algorithm: {public_key.__class__.__name__.lower()}"
                )

            # If verification succeeds, return the certificate
            matching_certificate_verified = matching_certificate.chosen.dump()

        except InvalidSignature:
            logger.info(
                f"The public key of the certificate: {hashlib.sha256(matching_certificate.chosen.dump()).hexdigest()} "
                f"is not associated with the signature!"
            )

        return matching_certificate_verified

    @staticmethod
    def get_hash_algorithm(signer_info):
        # Determine the hash algorithm from the SignerInfo
        digest_algorithm = signer_info['digest_algorithm']['algorithm'].native
        # Map the digest algorithm to a hash function
        hash_algorithms = {
            'md5': (md5, hashes.MD5),
            'sha1': (sha1, hashes.SHA1),
            'sha224': (sha224, hashes.SHA224),
            'sha256': (sha256, hashes.SHA256),
            'sha384': (sha384, hashes.SHA384),
            'sha512': (sha512, hashes.SHA512),
        }
        if digest_algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {digest_algorithm}")
        return hash_algorithms[digest_algorithm]

    def find_certificate(self, signed_data_certificates, signer_info):
        """
        From the bag of certs, obtain the certificate referenced by the SignerInfo.

        Args:
            signed_data_certificates: List of certificates in the SignedData.
            signer_info: SignerInfo object containing the issuer and serial number reference.

        Returns:
            The matching certificate if found, otherwise None.
        """
        matching_certificate = None
        issuer_and_serial_number = signer_info['sid']
        issuer_str = self.canonical_name(
            issuer_and_serial_number.chosen['issuer']
        )
        serial_number = issuer_and_serial_number.native['serial_number']

        # # Create a x509.Name object for the issuer in the SignerInfo
        # issuer_name = x509.Name.build(issuer)
        # issuer_str = self.canonical_name(issuer_name)

        for cert in signed_data_certificates:
            if cert.name == 'certificate':
                cert_issuer = self.canonical_name(
                    cert.chosen['tbs_certificate']['issuer']
                )
                cert_serial_number = cert.native['tbs_certificate'][
                    'serial_number'
                ]

                # Compare the canonical string representations of the issuers and the serial numbers
                if (
                    cert_issuer == issuer_str
                    and cert_serial_number == serial_number
                ):
                    matching_certificate = cert
                    break

        return matching_certificate

    def get_certificate(self, filename: str) -> Union[x509.Certificate, None]:
        """
        Return a X.509 certificate object by giving the name in the apk file

        :param filename: filename of the signature file in the APK
        :returns: a :class:`Certificate` certificate
        """
        cert = self.get_certificate_der(filename)
        if cert:
            certificate = x509.Certificate.load(cert)
        else:
            certificate = None
        return certificate

    def canonical_name(self, name: Any, android: bool = False) -> str:
        """
        /*
         * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
         * The original author has granted permission to use this code snippet under the
         * Apache License 2.0 for inclusion in this project.
         * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
         */
         Canonical representation of x509.Name as str (with raw control characters
        in places those are not stripped by normalisation).
        """
        # return ",".join("+".join(f"{t}:{v}" for _, t, v in avas) for avas in self.comparison_name(name))
        return ",".join(
            "+".join(f"{t}={v}" for t, v in avas)
            for avas in self.comparison_name(name, android=android)
        )

    def comparison_name(
        self, name: x509.Name, *, android: bool = False
    ) -> List[List[Tuple[str, str]]]:
        """
        /*
         * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
         * The original author has granted permission to use this code snippet under the
         * Apache License 2.0 for inclusion in this project.
         * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
         */
        Canonical representation of x509.Name as nested list.

        Returns a list of RDNs which are a list of AVAs which are a (type, value)
        tuple, where type is the standard name or dotted OID, and value is the
        normalised string representation of the value.
        """

        return [
            [(t, nv) for _, t, nv, _ in avas]
            for avas in self.x509_ordered_name(name, android=android)
        ]

    @staticmethod
    def x509_ordered_name(
        name: x509.Name,
        *,  # type: ignore[no-any-unimported]
        android: bool = False,
    ) -> List[List[Tuple[int, str, str, str]]]:
        """
         /*
         * Method is dual-licensed under the Apache License 2.0 and GPLv3+.
         * The original author has granted permission to use this code snippet under the
         * Apache License 2.0 for inclusion in this project.
         * https://github.com/obfusk/x509_canonical_name.py/blob/master/x509_canonical_name.py
         */
        Representation of x509.Name as nested list, in canonical ordering (but also
        including non-canonical pre-normalised string values).

        Returns a list of RDNs which are a list of AVAs which are a (oid, type,
        normalised_value, esc_value) tuple, where oid is 0 for standard names and 1
        for dotted OIDs, type is the standard name or dotted OID, normalised_value
        is the normalised string representation of the value, and esc_value is the
        string value before normalisation (but after escaping).

        NB: control characters are not escaped, only characters in ",+<>;\"\\" and
        "#" at the start (before "whitespace" trimming) are.

        https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName(java.lang.String)
        https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/AVA.java#L805
        https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/RDN.java#L472
        https://android.googlesource.com/platform/libcore/+/refs/heads/android14-release/ojluni/src/main/java/sun/security/x509/RDN.java#481
        """

        def key(
            ava: Tuple[int, str, str, str]
        ) -> Tuple[int, Union[str, List[int]], str]:
            o, t, nv, _ = ava
            if android and o:
                return o, [int(x) for x in t.split(".")], nv
            return o, t, nv

        DS, U8, PS = (
            x509.DirectoryString,
            x509.UTF8String,
            x509.PrintableString,
        )
        oids = {
            "2.5.4.3": ("common_name", "cn"),
            "2.5.4.6": ("country_name", "c"),
            "2.5.4.7": ("locality_name", "l"),
            "2.5.4.8": ("state_or_province_name", "st"),
            "2.5.4.9": ("street_address", "street"),
            "2.5.4.10": ("organization_name", "o"),
            "2.5.4.11": ("organizational_unit_name", "ou"),
            "0.9.2342.19200300.100.1.1": ("user_id", "uid"),
            "0.9.2342.19200300.100.1.25": ("domain_component", "dc"),
        }
        esc = {ord(c): f"\\{c}" for c in ",+<>;\"\\"}
        cws = "".join(
            chr(i) for i in range(32 + 1)
        )  # control (but not esc) and whitespace
        data = []
        for rdn in reversed(name.chosen):
            avas = []
            for ava in rdn:
                at, av = ava["type"], ava["value"]
                if at.dotted in oids:
                    o, t = 0, oids[at.dotted][1]  # order standard before OID
                else:
                    o, t = 1, at.dotted
                if o or not (
                    isinstance(av, DS) and isinstance(av.chosen, (U8, PS))
                ):
                    ev = nv = "#" + binascii.hexlify(av.dump()).decode()
                else:
                    ev = (av.native or "").translate(esc)
                    if ev.startswith("#"):
                        ev = "\\" + ev
                    nv = unicodedata.normalize(
                        "NFKD",
                        re.sub(r" +", " ", ev).strip(cws).upper().lower(),
                    )
                avas.append((o, t, nv, ev))
            data.append(sorted(avas, key=key))
        return data

    def new_zip(
        self,
        filename: str,
        deleted_files: Union[str, None] = None,
        new_files: dict = {},
    ) -> None:
        """
        Create a new zip file

        :param filename: the output filename of the zip
        :param deleted_files: a regex pattern to remove specific file
        :param new_files: a dictionnary of new files

        :type filename: string
        :type deleted_files: None or a string
        :type new_files: a dictionnary (key:filename, value:content of the file)
        """
        zout = zipfile.ZipFile(filename, 'w')

        for item in self.zip.infolist():
            # Block one: deleted_files, or deleted_files and new_files
            if deleted_files is not None:
                if re.match(deleted_files, item) is None:
                    # if the regex of deleted_files doesn't match the filename
                    if new_files is not False:
                        if item in new_files:
                            # and if the filename is in new_files
                            zout.writestr(item, new_files[item])
                            continue
                    # Otherwise, write the original file.
                    buffer = self.zip.read(item)
                    zout.writestr(item, buffer)
            # Block two: deleted_files is None, new_files is not empty
            elif new_files is not False:
                if item in new_files:
                    zout.writestr(item, new_files[item])
                else:
                    buffer = self.zip.read(item)
                    zout.writestr(item, buffer)
            # Block three: deleted_files is None, new_files is empty.
            # Just write out the default zip
            else:
                buffer = self.zip.read(item)
                zout.writestr(item, buffer)
        zout.close()

    def get_android_manifest_axml(self) -> Union[AXMLPrinter, None]:
        """
        Return the :class:`AXMLPrinter` object which corresponds to the AndroidManifest.xml file

        :rtype: :class:`~androguard.core.axml.AXMLPrinter`
        """
        try:
            return self.axml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_manifest_xml(self) -> Union[lxml.etree.Element, None]:
        """
        Return the parsed xml object which corresponds to the AndroidManifest.xml file

        :rtype: :class:`~lxml.etree.Element`
        """
        try:
            return self.xml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_resources(self) -> Union[ARSCParser, None]:
        """
        Return the :class:`~androguard.core.axml.ARSCParser` object which corresponds to the resources.arsc file

        :rtype: :class:`~androguard.core.axml.ARSCParser`
        """
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            if "resources.arsc" not in self.zip.namelist():
                # There is a rare case, that no resource file is supplied.
                # Maybe it was added manually, thus we check here
                return None
            self.arsc["resources.arsc"] = ARSCParser(
                self.zip.read("resources.arsc")
            )
            return self.arsc["resources.arsc"]

    def is_signed(self) -> bool:
        """
        Returns true if any of v1, v2, or v3 signatures were found.
        """
        return (
            self.is_signed_v1() or self.is_signed_v2() or self.is_signed_v3()
        )

    def is_signed_v1(self) -> bool:
        """
        Returns true if a v1 / JAR signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        return self.get_signature_name() is not None

    def is_signed_v2(self) -> bool:
        """
        Returns true of a v2 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v2 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v2

    def is_signed_v3(self) -> bool:
        """
        Returns true of a v3 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v3 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v3

    def read_uint32_le(self, io_stream) -> int:
        (value,) = unpack('<I', io_stream.read(4))
        return value

    def parse_signatures_or_digests(
        self, digest_bytes
    ) -> list[tuple[int, bytes]]:
        """Parse digests"""

        if not len(digest_bytes):
            return []

        digests = []
        block = io.BytesIO(digest_bytes)

        data_len = self.read_uint32_le(block)
        while block.tell() < data_len:

            algorithm_id = self.read_uint32_le(block)
            digest_len = self.read_uint32_le(block)
            digest = block.read(digest_len)

            digests.append((algorithm_id, digest))

        return digests

    def parse_v2_v3_signature(self) -> None:
        # Need to find an v2 Block in the APK.
        # The Google Docs gives you the following rule:
        # * go to the end of the ZIP File
        # * search for the End of Central directory
        # * then jump to the beginning of the central directory
        # * Read now the magic of the signing block
        # * before the magic there is the size_of_block, so we can jump to
        # the beginning.
        # * There should be again the size_of_block
        # * Now we can read the Key-Values
        # * IDs with an unknown value should be ignored.
        f = io.BytesIO(self.get_raw())

        size_central = None
        offset_central = None

        # Go to the end
        f.seek(-1, io.SEEK_END)
        # we know the minimal length for the central dir is 16+4+2
        f.seek(-20, io.SEEK_CUR)

        while f.tell() > 0:
            f.seek(-1, io.SEEK_CUR)
            (r,) = unpack('<4s', f.read(4))
            if r == self._PK_END_OF_CENTRAL_DIR:
                # Read central dir
                (
                    this_disk,
                    disk_central,
                    this_entries,
                    total_entries,
                    size_central,
                    offset_central,
                ) = unpack('<HHHHII', f.read(16))
                # TODO according to the standard we need to check if the
                # end of central directory is the last item in the zip file
                # TODO We also need to check if the central dir is exactly
                # before the end of central dir...

                # These things should not happen for APKs
                if this_disk != 0:
                    logger.warning(
                        "This is a multi disk ZIP! Attempting to process its signature anyway!"
                    )
                if disk_central != 0:
                    logger.warning(
                        "This is a multi disk ZIP! Attempting to process its signature anyway!"
                    )
                break
            f.seek(-4, io.SEEK_CUR)

        if not offset_central:
            return

        f.seek(offset_central)
        (r,) = unpack('<4s', f.read(4))
        f.seek(-4, io.SEEK_CUR)
        if r != self._PK_CENTRAL_DIR:
            raise BrokenAPKError("No Central Dir at specified offset")

        # Go back and check if we have a magic
        end_offset = f.tell()
        f.seek(-24, io.SEEK_CUR)
        size_of_block, magic = unpack('<Q16s', f.read(24))

        self._is_signed_v2 = False
        self._is_signed_v3 = False

        if magic != self._APK_SIG_MAGIC:
            return

        # go back size_of_blocks + 8 and read size_of_block again
        f.seek(-(size_of_block + 8), io.SEEK_CUR)
        (size_of_block_start,) = unpack("<Q", f.read(8))
        if size_of_block_start != size_of_block:
            raise BrokenAPKError("Sizes at beginning and and does not match!")

        # Store all blocks
        while f.tell() < end_offset - 24:
            size, key = unpack('<QI', f.read(12))
            value = f.read(size - 4)
            if key in self._v2_blocks:
                # TODO: Store the duplicate V2 Signature blocks and offer a way to show them
                # https://github.com/androguard/androguard/issues/1030
                logger.warning(
                    "Duplicate block ID in APK Signing Block: {}".format(key)
                )
            else:
                self._v2_blocks[key] = value

        # Test if a signature is found
        if self._APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True

        if self._APK_SIG_KEY_V3_SIGNATURE in self._v2_blocks:
            self._is_signed_v3 = True

    def parse_v3_signing_block(self) -> None:
        """
        Parse the V2 signing block and extract all features
        """

        self._v3_signing_data = []

        # calling is_signed_v3 should also load the signature, if any
        if not self.is_signed_v3():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V3_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V3 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed)
        #        * certificates
        #        * minSDK
        #        * maxSDK
        #        * additional attributes
        #    * minSDK
        #    * maxSDK
        #    * signatures
        #    * publickey
        size_sequence = self.read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError(
                "size of sequence and blocksize does not match"
            )

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = self.read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = self.read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = self.read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = self.parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = self.read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:

                len_cert = self.read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # versions
            signed_data_min_sdk = self.read_uint32_le(signed_data)
            signed_data_max_sdk = self.read_uint32_le(signed_data)

            # Addional attributes
            len_attr = self.read_uint32_le(signed_data)
            attr = signed_data.read(len_attr)

            signed_data_object = APKV3SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attr
            signed_data_object.minSDK = signed_data_min_sdk
            signed_data_object.maxSDK = signed_data_max_sdk

            # versions (should be the same as signed data's versions)
            signer_min_sdk = self.read_uint32_le(block)
            signer_max_sdk = self.read_uint32_le(block)

            # Signatures
            len_sigs = self.read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = self.parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = self.read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV3Signer()
            signer._bytes = view[off_signer: off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey
            signer.minSDK = signer_min_sdk
            signer.maxSDK = signer_max_sdk

            self._v3_signing_data.append(signer)

    def parse_v2_signing_block(self) -> None:
        """
        Parse the V2 signing block and extract all features
        """

        self._v2_signing_data = []

        # calling is_signed_v2 should also load the signature
        if not self.is_signed_v2():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V2_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V2 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed)
        #        * certificates
        #        * additional attributes
        #    * signatures
        #    * publickey

        size_sequence = self.read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError(
                "size of sequence and blocksize does not match"
            )

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = self.read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = self.read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = self.read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = self.parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = self.read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:
                len_cert = self.read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # Additional attributes
            len_attr = self.read_uint32_le(signed_data)
            attributes = signed_data.read(len_attr)

            signed_data_object = APKV2SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attributes

            # Signatures
            len_sigs = self.read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = self.parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = self.read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV2Signer()
            signer._bytes = view[off_signer: off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey

            self._v2_signing_data.append(signer)

    def get_public_keys_der_v3(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        public_keys = []

        for signer in self._v3_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_public_keys_der_v2(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        public_keys = []

        for signer in self._v2_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_certificates_der_v3(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        certs = []
        for signed_data in [
            signer.signed_data for signer in self._v3_signing_data
        ]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_certificates_der_v2(self) -> list[bytes]:
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        certs = []
        for signed_data in [
            signer.signed_data for signer in self._v2_signing_data
        ]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_public_keys_v3(self) -> list[keys.PublicKeyInfo]:
        """
        Return a list of :class:`asn1crypto.keys.PublicKeyInfo` which are found
        in the v3 signing block.
        """
        return [
            keys.PublicKeyInfo.load(pkey)
            for pkey in self.get_public_keys_der_v3()
        ]

    def get_public_keys_v2(self) -> list[keys.PublicKeyInfo]:
        """
        Return a list of :class:`asn1crypto.keys.PublicKeyInfo` which are found
        in the v2 signing block.
        """
        return [
            keys.PublicKeyInfo.load(pkey)
            for pkey in self.get_public_keys_der_v2()
        ]

    def get_certificates_v3(self) -> list[x509.Certificate]:
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the v3 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        return [
            x509.Certificate.load(cert)
            for cert in self.get_certificates_der_v3()
        ]

    def get_certificates_v2(self) -> list[x509.Certificate]:
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the v2 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        return [
            x509.Certificate.load(cert)
            for cert in self.get_certificates_der_v2()
        ]

    def get_certificates_v1(self) -> list[Union[x509.Certificate, None]]:
        """
        Return a list of verified :class:`asn1crypto.x509.Certificate` which are found
        in the META-INF folder (v1 signing).
        """
        certs = []
        for x in self.get_signature_names():
            cc = self.get_certificate_der(x)
            if cc is not None:
                certs.append(x509.Certificate.load(cc))
        return certs

    def get_certificates(self) -> list[x509.Certificate]:
        """
        Return a list of unique :class:`asn1crypto.x509.Certificate` which are found
        in v1, v2 and v3 signing
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        Exception is v1, for which the certificate returned is verified.
        """
        fps = []
        certs = []
        for x in (
            self.get_certificates_v1()
            + self.get_certificates_v2()
            + self.get_certificates_v3()
        ):
            if x.sha256 not in fps:
                fps.append(x.sha256)
                certs.append(x)
        return certs

    def get_signature_name(self) -> Union[str, None]:
        """
        Return the name of the first signature file found.
        """
        if self.get_signature_names():
            return self.get_signature_names()[0]
        else:
            # Unsigned APK
            return None

    def get_signature_names(self) -> list[str]:
        """
        Return a list of the signature file names (v1 Signature / JAR
        Signature)

        :rtype: List of filenames matching a Signature
        """
        signature_expr = re.compile(r"^(META-INF/)(.*)(\.RSA|\.EC|\.DSA)$")
        signatures = []

        for i in self.get_files():
            if signature_expr.search(i):
                if "{}.SF".format(i.rsplit(".", 1)[0]) in self.get_files():
                    signatures.append(i)
                else:
                    logger.warning(
                        "v1 signature file {} missing .SF file - Partial signature!".format(
                            i
                        )
                    )

        return signatures

    def get_signature(self) -> Union[str, None]:
        """
        Return the data of the first signature file found (v1 Signature / JAR
        Signature)

        :rtype: First signature name or None if not signed
        """
        if self.get_signatures():
            return self.get_signatures()[0]
        else:
            return None

    def get_signatures(self) -> list[bytes]:
        """
        Return a list of the data of the signature files.
        Only v1 / JAR Signing.

        :rtype: list of bytes
        """
        signature_expr = re.compile(r"^(META-INF/)(.*)(\.RSA|\.EC|\.DSA)$")
        signature_datas = []

        for i in self.get_files():
            if signature_expr.search(i):
                signature_datas.append(self.get_file(i))

        return signature_datas

    def show(self) -> None:
        self.get_files_types()

        print("FILES: ")
        for i in self.get_files():
            try:
                print("\t", i, self._files[i], "%x" % self.files_crc32[i])
            except KeyError:
                print("\t", i, "%x" % self.files_crc32[i])

        print("DECLARED PERMISSIONS:")
        declared_permissions = self.get_declared_permissions()
        for i in declared_permissions:
            print("\t", i)

        print("REQUESTED PERMISSIONS:")
        requested_permissions = self.get_permissions()
        for i in requested_permissions:
            print("\t", i)

        print("MAIN ACTIVITY: ", self.get_main_activity())

        print("ACTIVITIES: ")
        activities = self.get_activities()
        for i in activities:
            filters = self.get_intent_filters("activity", i)
            print("\t", i, filters or "")

        print("SERVICES: ")
        services = self.get_services()
        for i in services:
            filters = self.get_intent_filters("service", i)
            print("\t", i, filters or "")

        print("RECEIVERS: ")
        receivers = self.get_receivers()
        for i in receivers:
            filters = self.get_intent_filters("receiver", i)
            print("\t", i, filters or "")

        print("PROVIDERS: ", self.get_providers())

        if self.is_signed_v1():
            print("CERTIFICATES v1:")
            for c in self.get_signature_names():
                show_Certificate(self.get_certificate(c))

        if self.is_signed_v2():
            print("CERTIFICATES v2:")
            for c in self.get_certificates_v2():
                show_Certificate(c)


def show_Certificate(cert, short: bool = False) -> None:
    """
    Print Fingerprints, Issuer and Subject of an X509 Certificate.

    :param cert: X509 Certificate to print
    :param short: Print in shortform for DN (Default: False)

    :type cert: :class:`asn1crypto.x509.Certificate`
    :type short: Boolean
    """
    print("SHA1 Fingerprint: {}".format(cert.sha1_fingerprint))
    print("SHA256 Fingerprint: {}".format(cert.sha256_fingerprint))
    print(
        "Issuer: {}".format(
            get_certificate_name_string(cert.issuer.native, short=short)
        )
    )
    print(
        "Subject: {}".format(
            get_certificate_name_string(cert.subject.native, short=short)
        )
    )


def ensure_final_value(packageName: str, arsc: ARSCParser, value: str) -> str:
    """Ensure incoming value is always the value, not the resid

    androguard will sometimes return the Android "resId" aka
    Resource ID instead of the actual value.  This checks whether
    the value is actually a resId, then performs the Android
    Resource lookup as needed.

    """
    if value:
        returnValue = value
        if value[0] == '@':
            # TODO: @packagename:DEADBEEF is not supported here!
            try:  # can be a literal value or a resId
                res_id = int('0x' + value[1:], 16)
                res_id = arsc.get_id(packageName, res_id)[1]
                returnValue = arsc.get_string(packageName, res_id)[1]
            except (ValueError, TypeError):
                pass
        return returnValue
    return ''


def get_apkid(apkfile: str) -> tuple[str, str, str]:
    """Read (appid, versionCode, versionName) from an APK

    This first tries to do quick binary XML parsing to just get the
    values that are needed.  It will fallback to full androguard
    parsing, which is slow, if it can't find the versionName value or
    versionName is set to a Android String Resource (e.g. an integer
    hex value that starts with @).

    """
    logger.debug("GET_APKID")

    if not os.path.exists(apkfile):
        logger.error("'{apkfile}' does not exist!".format(apkfile=apkfile))

    appid = None
    versionCode = None
    versionName = None
    apk = ZipEntry.parse(apkfile, False)
    manifest = apk.read('AndroidManifest.xml')
    axml = AXMLParser(manifest)
    count = 0
    while axml.is_valid():
        _type = next(axml)
        count += 1
        if _type == START_TAG:
            for i in range(0, axml.getAttributeCount()):
                name = axml.getAttributeName(i)
                _type = axml.getAttributeValueType(i)
                _data = axml.getAttributeValueData(i)
                value = format_value(
                    _type, _data, lambda _: axml.getAttributeValue(i)
                )
                if appid is None and name == 'package':
                    appid = value
                elif versionCode is None and name == 'versionCode':
                    if value.startswith('0x'):
                        versionCode = str(int(value, 16))
                    else:
                        versionCode = value
                elif versionName is None and name == 'versionName':
                    versionName = value

            if axml.name == 'manifest':
                break
        elif _type == END_TAG or _type == TEXT or _type == END_DOCUMENT:
            raise RuntimeError(
                '{path}: <manifest> must be the first element in AndroidManifest.xml'.format(
                    path=apkfile
                )
            )

    if not versionName or versionName[0] == '@':
        a = APK(apkfile)
        versionName = ensure_final_value(
            a.package, a.get_android_resources(), a.get_androidversion_name()
        )
    if not versionName:
        versionName = ''  # versionName is expected to always be a str

    return appid, versionCode, versionName.strip('\0')
