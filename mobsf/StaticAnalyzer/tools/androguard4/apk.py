# -*- coding: utf_8 -*-
# flake8: noqa
# Androguard

from .axml import ARSCParser, AXMLPrinter, ARSCResTableConfig
from .zipfile import ZipEntry

# Python core
import io
from zlib import crc32
import os
import re
import binascii
import zipfile
from struct import unpack
import hashlib
import asn1crypto
import logging

# External dependecies
import lxml.sax
from xml.dom.pulldom import SAX2DOM
# Used for reading Certificates
from asn1crypto import cms, x509, keys

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree


def get_certificate_name_string(name, short=False, delimiter=', '):
    """
    Function from androguard.

    licensed  under the Apache License, Version 2.0.
    https://github.com/androguard/androguard/blob/master/androguard/util.py
    Format the Name type of a X509 Certificate in a human readable form.

    :param name: Name object to return the DN from
    :param short: Use short form (default: False)
    :param delimiter: Delimiter string or character between
        two parts (default: ', ')

    :type name: dict or :class:`asn1crypto.x509.Name`
    :type short: boolean
    :type delimiter: str

    :rtype: str
    """
    if isinstance(name, asn1crypto.x509.Name):
        name = name.native

    # For the shortform, we have a lookup table
    # See RFC4514 for more details
    _ = {
        'business_category': ('businessCategory', 'businessCategory'),
        'serial_number': ('serialNumber', 'serialNumber'),
        'country_name': ('C', 'countryName'),
        'postal_code': ('postalCode', 'postalCode'),
        'state_or_province_name': ('ST', 'stateOrProvinceName'),
        'locality_name': ('L', 'localityName'),
        'street_address': ('street', 'streetAddress'),
        'organization_name': ('O', 'organizationName'),
        'organizational_unit_name': ('OU', 'organizationalUnitName'),
        'title': ('title', 'title'),
        'common_name': ('CN', 'commonName'),
        'initials': ('initials', 'initials'),
        'generation_qualifier': ('generationQualifier', 'generationQualifier'),
        'surname': ('SN', 'surname'),
        'given_name': ('GN', 'givenName'),
        'name': ('name', 'name'),
        'pseudonym': ('pseudonym', 'pseudonym'),
        'dn_qualifier': ('dnQualifier', 'dnQualifier'),
        'telephone_number': ('telephoneNumber', 'telephoneNumber'),
        'email_address': ('E', 'emailAddress'),
        'domain_component': ('DC', 'domainComponent'),
        'name_distinguisher': ('nameDistinguisher', 'nameDistinguisher'),
        'organization_identifier': (
            'organizationIdentifier', 'organizationIdentifier'),
    }
    return delimiter.join(
        ['{}={}'.format(
            _.get(attr, (attr, attr))[0 if short else 1],
            name[attr]) for attr in name])


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
    """ try to parse additional attributes, but ends up to hexdump if the scheme is unknown """

    attributes_raw = io.BytesIO(additional_attributes)
    attributes_hex = binascii.hexlify(additional_attributes)

    if not len(additional_attributes):
        return attributes_hex

    len_attribute, = unpack('<I', attributes_raw.read(4))
    if len_attribute != 8:
        return attributes_hex

    attr_id, = unpack('<I', attributes_raw.read(4))
    if attr_id != APK._APK_SIG_ATTR_V2_STRIPPING_PROTECTION:
        return attributes_hex

    scheme_id, = unpack('<I', attributes_raw.read(4))

    return "stripping protection set, scheme %d" % scheme_id


def _dump_digests_or_signatures(digests_or_sigs):

    infos = ""
    for i,dos in enumerate(digests_or_sigs):

        infos += "\n"
        infos += " [%d]\n" % i
        infos += "  - Signature Id : %s\n" % APK._APK_SIG_ALGO_IDS.get(dos[0], hex(dos[0]))
        infos += "  - Digest: %s" % binascii.hexlify(dos[1])

    return infos


class APKV2SignedData:
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.digests = None
        self.certificates =  None
        self.additional_attributes = None

    def __str__(self):

        certs_infos = ""

        for i,cert in enumerate(self.certificates):
            x509_cert = x509.Certificate.load(cert)

            certs_infos += "\n"
            certs_infos += " [%d]\n" % i
            certs_infos += "  - Issuer: %s\n" % get_certificate_name_string(x509_cert.issuer, short=True)
            certs_infos += "  - Subject: %s\n" % get_certificate_name_string(x509_cert.subject, short=True)
            certs_infos += "  - Serial Number: %s\n" % hex(x509_cert.serial_number)
            certs_infos += "  - Hash Algorithm: %s\n" % x509_cert.hash_algo
            certs_infos += "  - Signature Algorithm: %s\n" % x509_cert.signature_algo
            certs_infos += "  - Valid not before: %s\n" % x509_cert['tbs_certificate']['validity']['not_before'].native
            certs_infos += "  - Valid not after: %s" % x509_cert['tbs_certificate']['validity']['not_after'].native

        return "\n".join([
            'additional_attributes : {}'.format(_dump_additional_attributes(self.additional_attributes)),
            'digests : {}'.format(_dump_digests_or_signatures(self.digests)),
            'certificates : {}'.format(certs_infos),
        ])


class APKV3SignedData(APKV2SignedData):
    """
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


class APKV2Signer:
    """
    This class holds all data associated with an APK V2 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.signed_data = None
        self.signatures = None
        self.public_key = None

    def __str__(self):
        return "\n".join([
            '{:s}'.format(str(self.signed_data)),
            'signatures : {}'.format(_dump_digests_or_signatures(self.signatures)),
            'public key : {}'.format(binascii.hexlify(self.public_key)),
        ])


class APKV3Signer(APKV2Signer):
    """
    This class holds all data associated with an APK V3 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):

        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


class APK:
    # Constants in ZipFile
    _PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
    _PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

    # Constants in the APK Signature Block
    _APK_SIG_MAGIC = b"APK Sig Block 42"
    _APK_SIG_KEY_V2_SIGNATURE = 0x7109871a
    _APK_SIG_KEY_V3_SIGNATURE = 0xf05368c0
    _APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xbeeff00d

    _APK_SIG_ALGO_IDS = {
        0x0101 : "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102 : "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        0x0103 : "RSASSA-PKCS1-v1_5 with SHA2-256 digest.", # This is for build systems which require deterministic signatures.
        0x0104 : "RSASSA-PKCS1-v1_5 with SHA2-512 digest.", # This is for build systems which require deterministic signatures.
        0x0201 : "ECDSA with SHA2-256 digest",
        0x0202 : "ECDSA with SHA2-512 digest",
        0x0301 : "DSA with SHA2-256 digest",
    }

    __no_magic = False

    def __init__(self, filename, raw=False, magic_file=None, skip_analysis=False, testzip=False):
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
            logger.warning("You set magic_file but this parameter is actually unused. You should remove it.")

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
            logger.info("Testing zip file integrity, this might take a while...")
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
                raise BrokenAPKError("The APK is probably broken: testzip returned an error.")

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
                logger.error("Error while parsing AndroidManifest.xml - is the file valid?")
                return

            self.axml[i] = ap
            self.xml[i] = self.axml[i].get_xml_obj()

            if self.axml[i].is_packed():
                logger.warning("XML Seems to be packed, operations on the AndroidManifest.xml might fail.")

            if self.xml[i] is not None:
                if self.xml[i].tag != "manifest":
                    logger.error("AndroidManifest.xml does not start with a <manifest> tag! Is this a valid APK?")
                    return

                self.package = self.get_attribute_value("manifest", "package")
                self.androidversion["Code"] = self.get_attribute_value("manifest", "versionCode")
                self.androidversion["Name"] = self.get_attribute_value("manifest", "versionName")
                permission = list(self.get_all_attribute_value("uses-permission", "name"))
                self.permissions = list(set(self.permissions + permission))

                for uses_permission in self.find_tags("uses-permission"):
                    self.uses_permissions.append([
                        self.get_value_from_tag(uses_permission, "name"),
                        self._get_permission_maxsdk(uses_permission)
                    ])

                # getting details of the declared permissions
                for d_perm_item in self.find_tags('permission'):
                    d_perm_name = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "name")))
                    d_perm_label = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "label")))
                    d_perm_description = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "description")))
                    d_perm_permissionGroup = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "permissionGroup")))
                    d_perm_protectionLevel = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "protectionLevel")))

                    d_perm_details = {
                        "label": d_perm_label,
                        "description": d_perm_description,
                        "permissionGroup": d_perm_permissionGroup,
                        "protectionLevel": d_perm_protectionLevel,
                    }
                    self.declared_permissions[d_perm_name] = d_perm_details

                self.valid_apk = True
                logger.debug("APK file was successfully validated!")

        # self.permission_module = androconf.load_api_specific_resource_module(
        #     "aosp_permissions", self.get_target_sdk_version())
        # self.permission_module_min_sdk = androconf.load_api_specific_resource_module(
        #     "aosp_permissions", self.get_min_sdk_version())

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
            logger.warning(str(maxSdkVersion) + ' is not a valid value for <uses-permission> maxSdkVersion')
        except TypeError:
            pass
        return maxSdkVersion

    def is_valid_APK(self):
        """
        Return true if the APK is valid, false otherwise.
        An APK is seen as valid, if the AndroidManifest.xml could be successful parsed.
        This does not mean that the APK has a valid signature nor that the APK
        can be installed on an Android system.

        :rtype: boolean
        """
        return self.valid_apk

    def get_filename(self):
        """
        Return the filename of the APK

        :rtype: :class:`str`
        """
        return self.filename

    def get_app_name(self):
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
            app_name = self.get_attribute_value('activity', 'label', name=main_activity_name)

        if app_name is None:
            # No App name set
            # TODO return packagename instead?
            logger.warning("It looks like that no app name is set for the main activity!")
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
                    logger.warning("Resource ID with android package name encountered! "
                                "Will not resolve, framework-res.apk would be required.")
                    return app_name
                else:
                    # TODO should look this up, might be in the resources
                    logger.warning("Resource ID with Package name '{}' encountered! Will not resolve".format(package))
                    return app_name

            try:
                app_name = res_parser.get_resolved_res_configs(
                    res_id,
                    ARSCResTableConfig.default_config())[0][1]
            except Exception as e:
                logger.warning("Exception selecting app name: %s" % e)
        return app_name

    def get_app_icon(self, max_dpi=65536):
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
            'activity', 'icon', name=main_activity_name)

        if not app_icon:
            app_icon = self.get_attribute_value('application', 'icon')

        res_parser = self.get_android_resources()
        if not res_parser:
            # Can not do anything below this point to resolve...
            return None

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(self.package, 'mipmap', 'ic_launcher')
            if res_id:
                app_icon = "@%x" % res_id

        if not app_icon:
            res_id = res_parser.get_res_id_by_key(self.package, 'drawable', 'ic_launcher')
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

    def get_package(self):
        """
        Return the name of the package

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.package

    def get_androidversion_code(self):
        """
        Return the android version code

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self):
        """
        Return the android version name

        This information is read from the AndroidManifest.xml

        :rtype: :class:`str`
        """
        return self.androidversion["Name"]

    def get_files(self):
        """
        Return the file names inside the APK.

        :rtype: a list of :class:`str`
        """
        return self.zip.namelist()

    # def _get_file_magic_name(self, buffer):
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
    #         logger.warning("It looks like you have the magic python package installed but not the magic library itself!")
    #         logger.warning("Error from magic library: %s", e)
    #         logger.warning("Please follow the installation instructions at https://github.com/ahupp/python-magic/#installation")
    #         logger.warning("You can also install the 'python-magic-bin' package on Windows and MacOS")
    #         return default

        try:
            # There are several implementations of magic,
            # unfortunately all called magic
            # We use this one: https://github.com/ahupp/python-magic/
            # You can also use python-magic-bin on Windows or MacOS
            getattr(magic, "MagicException")
        except AttributeError:
            self.__no_magic = True
            logger.warning("Not the correct Magic library was found on your "
                        "system. Please install python-magic or python-magic-bin!")
            return default

        try:
            # 1024 byte are usually enough to test the magic
            ftype = magic.from_buffer(buffer[:1024])
        except magic.MagicException as e:
            logger.exception("Error getting the magic type: %s", e)
            return default

        if not ftype:
            return default
        else:
            return self._patch_magic(buffer, ftype)

    @property
    def files(self):
        """
        Returns a dictionary of filenames and detected magic type

        :returns: dictionary of files and their mime type
        """
        return self.get_files_types()

    # def get_files_types(self):
    #     """
    #     Return the files inside the APK with their associated types (by using python-magic)

    #     At the same time, the CRC32 are calculated for the files.

    #     :rtype: a dictionnary
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
    #     if ("Zip" in orig) or ('(JAR)' in orig) and androconf.is_android_raw(buffer) == 'APK':
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
            if self.files_crc32[filename] != self.zip.infolist()[filename].crc32_of_uncompressed_data:
                logger.error("File '{}' has different CRC32 after unpacking! "
                          "Declared: {:08x}, Calculated: {:08x}".format(filename,
                                                                        self.zip.infolist()[filename].crc32_of_uncompressed_data,
                                                                        self.files_crc32[filename]))
        return buffer

    def get_files_crc32(self):
        """
        Calculates and returns a dictionary of filenames and CRC32

        :returns: dict of filename: CRC32
        """
        if self.files_crc32 == {}:
            for i in self.get_files():
                self._get_crc32(i)

        return self.files_crc32

    # def get_files_information(self):
    #     """
    #     Return the files inside the APK with their associated types and crc32

    #     :rtype: str, str, int
    #     """
    #     for k in self.get_files():
    #         yield k, self.get_files_types()[k], self.get_files_crc32()[k]

    def get_raw(self):
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

    def get_file(self, filename):
        """
        Return the raw data of the specified filename
        inside the APK

        :rtype: bytes
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self):
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

    def get_dex_names(self):
        """
        Return the names of all DEX files found in the APK.
        This method only accounts for "offical" dex files, i.e. all files
        in the root directory of the APK named classes.dex or classes[0-9]+.dex

        :rtype: a list of str
        """
        dexre = re.compile(r"^classes(\d*).dex$")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self):
        """
        Return the raw data of all classes dex files

        :rtype: a generator of bytes
        """
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def is_multidex(self):
        """
        Test if the APK has multiple DEX files

        :returns: True if multiple dex found, otherwise False
        """
        dexre = re.compile(r"^classes(\d+)?.dex$")
        return len([instance for instance in self.get_files() if dexre.search(instance)]) > 1

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
        self, tag_name, attribute, format_value=True, **attribute_filter
    ):
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
        self, tag_name, attribute, format_value=False, **attribute_filter
    ):
        """
        Return the attribute value in xml files which matches the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """

        for value in self.get_all_attribute_value(
                tag_name, attribute, format_value, **attribute_filter):
            if value is not None:
                return value

    def get_value_from_tag(self, tag, attribute):
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
                logger.warning("Failed to get the attribute '{}' on tag '{}' with namespace. "
                            "But found the same attribute without namespace!".format(attribute, tag.tag))
        return value

    def find_tags(self, tag_name, **attribute_filter):
        """
        Return a list of all the matched tags in all available xml

        :param str tag: specify the tag name
        """
        all_tags = [
            self.find_tags_from_xml(
                i, tag_name, **attribute_filter
            )
            for i in self.xml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tags_from_xml(
        self, xml_name, tag_name, **attribute_filter
    ):
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
            if self.is_tag_matched(
                xml.tag, **attribute_filter
            ):
                return [xml]
            return []
        tags = xml.findall(".//" + tag_name)
        return [
            tag for tag in tags if self.is_tag_matched(
                tag, **attribute_filter
            )
        ]

    def is_tag_matched(self, tag, **attribute_filter):
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

    def get_main_activities(self):
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
            activities_and_aliases = self.xml[i].findall(".//activity") + \
                                     self.xml[i].findall(".//activity-alias")

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

    def get_main_activity(self):
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
                main_activities.intersection(self.get_activities()))
            if good_main_activities:
                return good_main_activities[0]
            return sorted(main_activities)[0]
        return None

    def get_activities(self):
        """
        Return the android:name attribute of all activities

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("activity", "name"))

    def get_activity_aliases(self):
        """
        Return the android:name and android:targetActivity attribute of all activity aliases.

        :rtype: a list of dict
        """
        ali = []
        for alias in self.find_tags('activity-alias'):
            activity_alias = {}
            for attribute in ['name', 'targetActivity']:
                value = (alias.get(attribute) or
                         alias.get(self._ns(attribute)))
                if not value:
                    continue
                activity_alias[attribute] = self._format_value(value)
            if activity_alias:
                ali.append(activity_alias)
        return ali

    def get_services(self):
        """
        Return the android:name attribute of all services

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("service", "name"))

    def get_receivers(self):
        """
        Return the android:name attribute of all receivers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("receiver", "name"))

    def get_providers(self):
        """
        Return the android:name attribute of all providers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("provider", "name"))

    def get_res_value(self, name):
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
                res_id,
                ARSCResTableConfig.default_config())[0][1]
        except Exception as e:
            logger.warning("Exception get resolved resource id: %s" % e)
            return name

        return value

    def get_intent_filters(self, itemtype, name):
        """
        Find intent filters for a given item and name.

        Intent filter are attached to activities, services or receivers.
        You can search for the intent filters of such items and get a dictionary of all
        attached actions and intent categories.

        :param itemtype: the type of parent item to look for, e.g. `activity`,  `service` or `receiver`
        :param name: the `android:name` of the parent item, e.g. activity name
        :returns: a dictionary with the keys `action` and `category` containing the `android:name` of those items
        """
        attributes = {"action": ["name"], "category": ["name"], "data": ['scheme', 'host', 'port', 'path', 'pathPattern', 'pathPrefix', 'mimeType']}

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
                                if element == 'data': # multiple attributes
                                    values = {}
                                    for attribute in attributes[element]:
                                        value = ssitem.get(self._ns(attribute))
                                        if value:
                                            if value.startswith('@'):
                                                value = self.get_res_value(value)
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

    def get_permissions(self):
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

    def get_uses_implied_permission_list(self):
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

        if (WRITE_EXTERNAL_STORAGE in self.permissions or implied_WRITE_EXTERNAL_STORAGE) \
            and READ_EXTERNAL_STORAGE not in self.permissions:
            maxSdkVersion = None
            for name, version in self.uses_permissions:
                if name == WRITE_EXTERNAL_STORAGE:
                    maxSdkVersion = version
                    break
            implied.append([READ_EXTERNAL_STORAGE, maxSdkVersion])

        if target_sdk_version < 16:
            if READ_CONTACTS in self.permissions \
                and READ_CALL_LOG not in self.permissions:
                implied.append([READ_CALL_LOG, None])
            if WRITE_CONTACTS in self.permissions \
                and WRITE_CALL_LOG not in self.permissions:
                implied.append([WRITE_CALL_LOG, None])

        return implied

    def _update_permission_protection_level(self, protection_level, sdk_version):
        if not sdk_version or int(sdk_version) <= 15:
            return protection_level.replace('Or', '|').lower()
        return protection_level

    def _fill_deprecated_permissions(self, permissions):
        min_sdk = self.get_min_sdk_version()
        target_sdk = self.get_target_sdk_version()
        filled_permissions = permissions.copy()
        for permission in filled_permissions:
            protection_level, label, description = filled_permissions[permission]
            if ((not label or not description) 
                and permission in self.permission_module_min_sdk):
                x = self.permission_module_min_sdk[permission]
                protection_level = self._update_permission_protection_level(
                    x['protectionLevel'], min_sdk)
                filled_permissions[permission] = [
                    protection_level, x['label'], x['description']]
            else:
                filled_permissions[permission] = [
                    self._update_permission_protection_level(
                            protection_level, target_sdk),
                    label, description]
        return filled_permissions

    def get_details_permissions(self):
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
            else:
                # FIXME: the permission might be signature, if it is defined by the app itself!
                l[i] = ["normal", "Unknown permission from android reference",
                        "Unknown permission from android reference"]
        return self._fill_deprecated_permissions(l)

    def get_requested_aosp_permissions(self):
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

    def get_requested_aosp_permissions_details(self):
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

    def get_requested_third_party_permissions(self):
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

    def get_declared_permissions(self):
        """
        Returns list of the declared permissions.

        :rtype: list of strings
        """
        return list(self.declared_permissions.keys())

    def get_declared_permissions_details(self):
        """
        Returns declared permissions with the details.

        :rtype: dict
        """
        return self.declared_permissions

    def get_max_sdk_version(self):
        """
            Return the android:maxSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "maxSdkVersion")

    def get_min_sdk_version(self):
        """
            Return the android:minSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "minSdkVersion")

    def get_target_sdk_version(self):
        """
            Return the android:targetSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "targetSdkVersion")

    def get_effective_target_sdk_version(self):
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

    def get_libraries(self):
        """
            Return the android:name attributes for libraries

            :rtype: list
        """
        return list(self.get_all_attribute_value("uses-library", "name"))

    def get_features(self):
        """
        Return a list of all android:names found for the tag uses-feature
        in the AndroidManifest.xml

        :returns: list
        """
        return list(self.get_all_attribute_value("uses-feature", "name"))

    def is_wearable(self):
        """
        Checks if this application is build for wearables by
        checking if it uses the feature 'android.hardware.type.watch'
        See: https://developer.android.com/training/wearables/apps/creating.html for more information.

        Not every app is setting this feature (not even the example Google provides),
        so it might be wise to not 100% rely on this feature.

        :returns: True if wearable, False otherwise
        """
        return 'android.hardware.type.watch' in self.get_features()

    def is_leanback(self):
        """
        Checks if this application is build for TV (Leanback support)
        by checkin if it uses the feature 'android.software.leanback'

        :returns: True if leanback feature is used, false otherwise
        """
        return 'android.software.leanback' in self.get_features()

    def is_androidtv(self):
        """
        Checks if this application does not require a touchscreen,
        as this is the rule to get into the TV section of the Play Store
        See: https://developer.android.com/training/tv/start/start.html for more information.

        :returns: True if 'android.hardware.touchscreen' is not required, False otherwise
        """
        return self.get_attribute_value('uses-feature', 'name', required="false", name="android.hardware.touchscreen") == "android.hardware.touchscreen"

    def get_certificate_der(self, filename):
        """
        Return the DER coded X.509 certificate from the signature file.

        :param filename: Signature filename in APK
        :returns: DER coded X.509 certificate as binary
        """
        pkcs7message = self.get_file(filename)

        pkcs7obj = cms.ContentInfo.load(pkcs7message)
        cert = pkcs7obj['content']['certificates'][0].chosen.dump()
        return cert

    def get_certificate(self, filename):
        """
        Return a X.509 certificate object by giving the name in the apk file

        :param filename: filename of the signature file in the APK
        :returns: a :class:`Certificate` certificate
        """
        cert = self.get_certificate_der(filename)
        certificate = x509.Certificate.load(cert)

        return certificate

    def new_zip(self, filename, deleted_files=None, new_files={}):
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

    def get_android_manifest_axml(self):
        """
            Return the :class:`AXMLPrinter` object which corresponds to the AndroidManifest.xml file

            :rtype: :class:`~androguard.core.bytecodes.axml.AXMLPrinter`
        """
        try:
            return self.axml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_manifest_xml(self):
        """
        Return the parsed xml object which corresponds to the AndroidManifest.xml file

        :rtype: :class:`~lxml.etree.Element`
        """
        try:
            return self.xml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_resources(self):
        """
        Return the :class:`~androguard.core.bytecodes.axml.ARSCParser` object which corresponds to the resources.arsc file

        :rtype: :class:`~androguard.core.bytecodes.axml.ARSCParser`
        """
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            if "resources.arsc" not in self.zip.namelist():
                # There is a rare case, that no resource file is supplied.
                # Maybe it was added manually, thus we check here
                return None
            self.arsc["resources.arsc"] = ARSCParser(self.zip.read("resources.arsc"))
            return self.arsc["resources.arsc"]

    def is_signed(self):
        """
        Returns true if any of v1, v2, or v3 signatures were found.
        """
        return self.is_signed_v1() or self.is_signed_v2() or self.is_signed_v3()

    def is_signed_v1(self):
        """
        Returns true if a v1 / JAR signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        return self.get_signature_name() is not None

    def is_signed_v2(self):
        """
        Returns true of a v2 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v2 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v2

    def is_signed_v3(self):
        """
        Returns true of a v3 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v3 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v3

    def read_uint32_le(self, io_stream):
        value, = unpack('<I', io_stream.read(4))
        return value

    def parse_signatures_or_digests(self, digest_bytes):
        """ Parse digests """

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

    def parse_v2_v3_signature(self):
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
            r, = unpack('<4s', f.read(4))
            if r == self._PK_END_OF_CENTRAL_DIR:
                # Read central dir
                this_disk, disk_central, this_entries, total_entries, \
                size_central, offset_central = unpack('<HHHHII', f.read(16))
                # TODO according to the standard we need to check if the
                # end of central directory is the last item in the zip file
                # TODO We also need to check if the central dir is exactly
                # before the end of central dir...

                # These things should not happen for APKs
                if this_disk != 0:
                    logger.warning("This is a multi disk ZIP! Attempting to process its signature anyway!")
                if disk_central != 0:
                    logger.warning("This is a multi disk ZIP! Attempting to process its signature anyway!")
                break
            f.seek(-4, io.SEEK_CUR)

        if not offset_central:
            return

        f.seek(offset_central)
        r, = unpack('<4s', f.read(4))
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
        size_of_block_start, = unpack("<Q", f.read(8))
        if size_of_block_start != size_of_block:
            raise BrokenAPKError("Sizes at beginning and and does not match!")

        # Store all blocks
        while f.tell() < end_offset - 24:
            size, key = unpack('<QI', f.read(12))
            value = f.read(size - 4)
            self._v2_blocks[key] = value

        # Test if a signature is found
        if self._APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True

        if self._APK_SIG_KEY_V3_SIGNATURE in self._v2_blocks:
            self._is_signed_v3 = True


    def parse_v3_signing_block(self):
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
            raise BrokenAPKError("size of sequence and blocksize does not match")

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
            signer._bytes = view[off_signer:off_signer+size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey
            signer.minSDK = signer_min_sdk
            signer.maxSDK = signer_max_sdk

            self._v3_signing_data.append(signer)

    def parse_v2_signing_block(self):
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
            raise BrokenAPKError("size of sequence and blocksize does not match")

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
            signer._bytes = view[off_signer:off_signer+size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey

            self._v2_signing_data.append(signer)

    def get_public_keys_der_v3(self):
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        public_keys = []

        for signer in self._v3_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_public_keys_der_v2(self):
        """
        Return a list of DER coded X.509 public keys from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        public_keys = []

        for signer in self._v2_signing_data:
            public_keys.append(signer.public_key)

        return public_keys

    def get_certificates_der_v3(self):
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v3_signing_data == None:
            self.parse_v3_signing_block()

        certs = []
        for signed_data in [signer.signed_data for signer in self._v3_signing_data]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_certificates_der_v2(self):
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        certs = []
        for signed_data in [signer.signed_data for signer in self._v2_signing_data]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_public_keys_v3(self):
        """
        Return a list of :class:`asn1crypto.keys.PublicKeyInfo` which are found
        in the v3 signing block.
        """
        return [ keys.PublicKeyInfo.load(pkey) for pkey in self.get_public_keys_der_v3()]

    def get_public_keys_v2(self):
        """
        Return a list of :class:`asn1crypto.keys.PublicKeyInfo` which are found
        in the v2 signing block.
        """
        return [ keys.PublicKeyInfo.load(pkey) for pkey in self.get_public_keys_der_v2()]

    def get_certificates_v3(self):
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the v3 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        return [ x509.Certificate.load(cert) for cert in self.get_certificates_der_v3()]

    def get_certificates_v2(self):
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the v2 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        return [ x509.Certificate.load(cert) for cert in self.get_certificates_der_v2()]

    def get_certificates_v1(self):
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the META-INF folder (v1 signing).
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        certs = []
        for x in self.get_signature_names():
            certs.append(x509.Certificate.load(self.get_certificate_der(x)))

        return certs

    def get_certificates(self):
        """
        Return a list of unique :class:`asn1crypto.x509.Certificate` which are found
        in v1, v2 and v3 signing
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        fps = []
        certs = []
        for x in self.get_certificates_v1() + self.get_certificates_v2() + self.get_certificates_v3():
            if x.sha256 not in fps:
                fps.append(x.sha256)
                certs.append(x)
        return certs

    def get_signature_name(self):
        """
            Return the name of the first signature file found.
        """
        if self.get_signature_names():
            return self.get_signature_names()[0]
        else:
            # Unsigned APK
            return None

    def get_signature_names(self):
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
                    logger.warning("v1 signature file {} missing .SF file - Partial signature!".format(i))

        return signatures

    def get_signature(self):
        """
        Return the data of the first signature file found (v1 Signature / JAR
        Signature)

        :rtype: First signature name or None if not signed
        """
        if self.get_signatures():
            return self.get_signatures()[0]
        else:
            return None

    def get_signatures(self):
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

    def show(self):
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


def show_Certificate(cert, short=False):
    """
        Print Fingerprints, Issuer and Subject of an X509 Certificate.

        :param cert: X509 Certificate to print
        :param short: Print in shortform for DN (Default: False)

        :type cert: :class:`asn1crypto.x509.Certificate`
        :type short: Boolean
    """
    print("SHA1 Fingerprint: {}".format(cert.sha1_fingerprint))
    print("SHA256 Fingerprint: {}".format(cert.sha256_fingerprint))
    print("Issuer: {}".format(get_certificate_name_string(cert.issuer.native, short=short)))
    print("Subject: {}".format(get_certificate_name_string(cert.subject.native, short=short)))


def ensure_final_value(packageName, arsc, value):
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
