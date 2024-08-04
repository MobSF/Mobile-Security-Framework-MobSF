from datetime import datetime
from enum import Enum

from django.db import models


class DjangoPermissions(Enum):
    SCAN = ('can_scan', 'Scan Files')
    SUPPRESS = ('can_suppress', 'Suppress Findings')
    DELETE = ('can_delete', 'Delete Scans')


P = DjangoPermissions


class RecentScansDB(models.Model):
    class Meta:
        """Meta class for RecentScansDB model."""

        permissions = (P.DELETE.value, P.SCAN.value)

    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    VERSION_NAME = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    TIMESTAMP = models.DateTimeField(default=datetime.now)
    SCAN_LOGS = models.TextField(default=[])


class StaticAnalyzerAndroid(models.Model):
    class Meta:
        """Meta class for StaticAnalyzerAndroid model."""

        permissions = (P.DELETE.value, P.SCAN.value)

    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    PACKAGE_NAME = models.TextField(default='')
    MAIN_ACTIVITY = models.TextField(default='')
    EXPORTED_ACTIVITIES = models.TextField(default='')
    BROWSABLE_ACTIVITIES = models.TextField(default={})
    ACTIVITIES = models.TextField(default=[])
    RECEIVERS = models.TextField(default=[])
    PROVIDERS = models.TextField(default=[])
    SERVICES = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    TARGET_SDK = models.CharField(max_length=50, default='')
    MAX_SDK = models.CharField(max_length=50, default='')
    MIN_SDK = models.CharField(max_length=50, default='')
    VERSION_NAME = models.CharField(max_length=100, default='')
    VERSION_CODE = models.CharField(max_length=50, default='')
    ICON_PATH = models.TextField(default='')
    PERMISSIONS = models.TextField(default={})
    MALWARE_PERMISSIONS = models.TextField(default={})
    CERTIFICATE_ANALYSIS = models.TextField(default={})
    MANIFEST_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    FILE_ANALYSIS = models.TextField(default=[])
    ANDROID_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    NIAP_ANALYSIS = models.TextField(default={})
    PERMISSION_MAPPING = models.TextField(default={})
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default={})
    FIREBASE_URLS = models.TextField(default=[])
    FILES = models.TextField(default=[])
    EXPORTED_COUNT = models.TextField(default={})
    APKID = models.TextField(default={})
    QUARK = models.TextField(default=[])
    TRACKERS = models.TextField(default={})
    PLAYSTORE_DETAILS = models.TextField(default={})
    NETWORK_SECURITY = models.TextField(default=[])
    SECRETS = models.TextField(default=[])


class StaticAnalyzerIOS(models.Model):
    class Meta:
        """Meta class for StaticAnalyzerIOS model."""

        permissions = (P.DELETE.value, P.SCAN.value)

    FILE_NAME = models.CharField(max_length=255, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    BUILD = models.TextField(default='')
    APP_VERSION = models.CharField(max_length=100, default='')
    SDK_NAME = models.CharField(max_length=50, default='')
    PLATFORM = models.CharField(max_length=50, default='')
    MIN_OS_VERSION = models.CharField(max_length=50, default='')
    BUNDLE_ID = models.TextField(default='')
    BUNDLE_URL_TYPES = models.TextField(default=[])
    BUNDLE_SUPPORTED_PLATFORMS = models.CharField(max_length=50, default=[])
    ICON_PATH = models.TextField(default='')
    INFO_PLIST = models.TextField(default='')
    BINARY_INFO = models.TextField(default={})
    PERMISSIONS = models.TextField(default={})
    ATS_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    MACHO_ANALYSIS = models.TextField(default={})
    DYLIB_ANALYSIS = models.TextField(default=[])
    FRAMEWORK_ANALYSIS = models.TextField(default=[])
    IOS_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    FILE_ANALYSIS = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    FILES = models.TextField(default=[])
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default=[])
    FIREBASE_URLS = models.TextField(default=[])
    APPSTORE_DETAILS = models.TextField(default={})
    SECRETS = models.TextField(default=[])
    TRACKERS = models.TextField(default={})


class StaticAnalyzerWindows(models.Model):
    class Meta:
        """Meta class for StaticAnalyzerWindows model."""

        permissions = (P.DELETE.value, P.SCAN.value)

    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PUBLISHER_NAME = models.TextField(default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    APP_VERSION = models.TextField(default='')
    ARCHITECTURE = models.TextField(default='')
    COMPILER_VERSION = models.TextField(default='')
    VISUAL_STUDIO_VERSION = models.TextField(default='')
    VISUAL_STUDIO_EDITION = models.TextField(default='')
    TARGET_OS = models.TextField(default='')
    APPX_DLL_VERSION = models.TextField(default='')
    PROJ_GUID = models.TextField(default='')
    OPTI_TOOL = models.TextField(default='')
    TARGET_RUN = models.TextField(default='')
    FILES = models.TextField(default=[])
    STRINGS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    BINARY_WARNINGS = models.TextField(default=[])


class SuppressFindings(models.Model):
    class Meta:
        """Meta class for SuppressFindings model."""

        permissions = (P.DELETE.value, P.SCAN.value, P.SUPPRESS.value)

    PACKAGE_NAME = models.CharField(max_length=260, default='')
    SUPPRESS_RULE_ID = models.TextField(default=[])
    SUPPRESS_FILES = models.TextField(default={})
    SUPPRESS_TYPE = models.TextField(default='')
