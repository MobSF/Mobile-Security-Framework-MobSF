"""Persist passive research independently of the MobSF analysis engine."""
from django.conf import settings
from django.db import models
from django.utils import timezone


class Program(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=160)
    rules = models.JSONField(default=dict)
    authorization_source = models.CharField(max_length=500, blank=True)
    authorized_at = models.DateTimeField(null=True, blank=True)
    approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)


class Analysis(models.Model):
    program = models.ForeignKey(
        Program, on_delete=models.CASCADE, related_name='analyses')
    checksum = models.CharField(max_length=32)
    package = models.CharField(max_length=500, blank=True)
    version = models.CharField(max_length=100, blank=True)
    platform = models.CharField(max_length=20)
    imported_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Import one result per program and artifact."""

        constraints = [models.UniqueConstraint(
            fields=['program', 'checksum'], name='bb_program_checksum')]


class Endpoint(models.Model):
    analysis = models.ForeignKey(
        Analysis, on_delete=models.CASCADE, related_name='endpoints')
    fingerprint = models.CharField(max_length=64)
    url = models.CharField(max_length=4096)
    host = models.CharField(max_length=253)
    path = models.CharField(max_length=2048)
    method = models.CharField(max_length=10, blank=True)
    methods = models.JSONField(default=list)
    parameters = models.JSONField(default=list)
    sources = models.JSONField(default=list)
    protocol = models.CharField(max_length=20, default='REST')
    observed = models.BooleanField(default=False)
    confidence = models.FloatField(default=0.5)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        """Deduplicate resource identities within an analysis."""

        constraints = [models.UniqueConstraint(
            fields=['analysis', 'fingerprint'], name='bb_analysis_endpoint')]


class Finding(models.Model):
    STATES = [(v, v) for v in (
        'NEW', 'IN_REVIEW', 'FALSE_POSITIVE', 'CONFIRMED', 'RESOLVED')]
    SEVERITIES = [(v, v) for v in (
        'info', 'low', 'medium', 'high', 'critical')]
    analysis = models.ForeignKey(
        Analysis, on_delete=models.CASCADE, related_name='findings')
    fingerprint = models.CharField(max_length=64)
    title = models.CharField(max_length=300)
    kind = models.CharField(max_length=80)
    severity = models.CharField(
        max_length=10, choices=SEVERITIES, default='info')
    confidence = models.FloatField(default=0.5)
    rationale = models.TextField()
    status = models.CharField(max_length=20, choices=STATES, default='NEW')
    review_note = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Keep heuristic identities separate from review state."""

        constraints = [models.UniqueConstraint(
            fields=['analysis', 'fingerprint'], name='bb_analysis_finding')]


class Evidence(models.Model):
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name='evidence')
    kind = models.CharField(max_length=30)
    source = models.CharField(max_length=500)
    content = models.JSONField(default=dict)
    sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    class Meta:
        """Deduplicate identical evidence and origin references."""

        constraints = [models.UniqueConstraint(
            fields=['finding', 'sha256', 'source'], name='bb_finding_evidence')]


class FindingEvent(models.Model):
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name='events')
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    previous_status = models.CharField(max_length=20)
    status = models.CharField(max_length=20)
    note = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
