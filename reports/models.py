import uuid
from django.db import models
from django.utils import timezone

class PhishingTelemetry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.CharField(max_length=255, null=True)
    schema_version = models.CharField(max_length=50, default="1.0.0")
    details = models.JSONField(null=True)
    normalized_summary = models.TextField(blank=True, null=True)
    enriched_flags = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "phishing_telemetry"
        indexes = [
            models.Index(fields=["source"]),
        ]

    def __str__(self):
        return f"Telemetry from {self.source} at {self.created_at}"


class PhishingReport(models.Model):  
    url = models.URLField(max_length=2048)
    screenshot = models.ImageField(upload_to='screenshots/', null=True, blank=True)
    whois_data = models.JSONField(null=True, blank=True)
    host_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'phishing_reports'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['url']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Report {self.id}: {self.url[:50]}..." 


class BankWebhook(models.Model):
    bank_name = models.CharField(max_length=255, unique=True)
    webhook_url = models.URLField()
    lifetimetoken = models.CharField(max_length=255)  # auth token provided by the bank
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'bank_webhook'

    def __str__(self):
        return self.bank_name
