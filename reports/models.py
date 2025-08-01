from django.db import models
from urllib.parse import urlparse

from django.utils import timezone


class PhishingReport(models.Model):
    url = models.URLField(help_text="The suspicious URL submitted")
    domain = models.CharField(max_length=255, blank=True, help_text="Extracted domain from the URL")
    description = models.TextField(blank=True, help_text="Optional description of the issue")

    screenshot = models.ImageField(
        upload_to='screenshots/',
        blank=True,
        null=True,
        help_text="Optional screenshot evidence"
    )

    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    browser_version = models.CharField(max_length=100, blank=True, help_text="Parsed browser version")
    extension_version = models.CharField(max_length=50, blank=True, help_text="Reported extension version")
    detected_by = models.CharField(max_length=100, default='unknown')

    #WHOIS API data fetching
    whois_registrar = models.CharField(max_length=255, blank=True, null=True)
    whois_creation_date = models.DateField(blank=True, null=True)
    whois_expiry_date = models.DateField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # ✅ Extract domain only (leave version parsing to views/serializers)
        if self.url:
            parsed_url = urlparse(self.url)
            self.domain = parsed_url.netloc

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.domain} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"



#Telemetry event model

class TelemetryEvent(models.Model):
    EVENT_TYPES = [
        ('report_submitted', 'Report Submitted'),
        ('extension_started', 'Extension Started'),
        ('error_occurred', 'Error Occurred'),
        ('feature_used', 'Feature Used'),
        # add more event types as needed
    ]

    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    timestamp = models.DateTimeField(default=timezone.now)
    metadata = models.JSONField(blank=True, null=True)  # flexible extra data

    def __str__(self):
        return f"{self.event_type} at {self.timestamp}"