from datetime import datetime

from django.db import models


class CyberspectScans(models.Model):
    """Model for storing Cyberspect scan data."""

    class Meta:
        """Meta class for CyberspectScans model."""

        app_label = 'StaticAnalyzer'

    ID = models.BigAutoField(primary_key=True)
    MOBSF_MD5 = models.CharField(max_length=32, null=True)
    DT_PROJECT_ID = models.UUIDField(null=True)
    SCHEDULED = models.BooleanField(null=False, default=False)
    INTAKE_START = models.DateTimeField(null=False)
    INTAKE_END = models.DateTimeField(null=True)
    SAST_START = models.DateTimeField(null=True)
    SAST_END = models.DateTimeField(null=True)
    SBOM_START = models.DateTimeField(null=True)
    SBOM_END = models.DateTimeField(null=True)
    DEPENDENCY_START = models.DateTimeField(null=True)
    DEPENDENCY_END = models.DateTimeField(null=True)
    NOTIFICATION_START = models.DateTimeField(null=True)
    NOTIFICATION_END = models.DateTimeField(null=True)
    SUCCESS = models.BooleanField(null=True)
    FAILURE_SOURCE = models.CharField(max_length=50, null=True)
    FAILURE_MESSAGE = models.TextField(null=True)
    FILE_SIZE_PACKAGE = models.IntegerField(null=True)
    FILE_SIZE_SOURCE = models.IntegerField(null=True)
    DEPENDENCY_TYPES = models.CharField(max_length=50, null=True)
    EMAIL = models.CharField(max_length=260, null=True)


class ApiKeys(models.Model):
    """Model for storing API keys."""

    class Meta:
        """Meta class for ApiKeys model."""

        app_label = 'StaticAnalyzer'

    class Role(models.IntegerChoices):
        """API Key role options."""

        UPLOAD_ONLY = 1
        READ_ONLY = 2
        FULL_ACCESS = 3

    ID = models.AutoField(primary_key=True)
    KEY_HASH = models.CharField(max_length=64, default='')
    KEY_PREFIX = models.CharField(max_length=5, default='')
    DESCRIPTION = models.CharField(max_length=100, default='')
    EMAIL = models.CharField(max_length=260, default='')
    ROLE = models.IntegerField(choices=Role.choices, default=Role.UPLOAD_ONLY)
    CREATE_DATE = models.DateTimeField(default=datetime.now)
    EXPIRE_DATE = models.DateTimeField(default=datetime.now)
    REVOKED_DATE = models.DateTimeField(null=True)
