from django.db import models

class PhishingReport(models.Model):
    url = models.URLField(help_text="The suspicious URL submitted")
    description = models.TextField(blank=True, help_text="Optional description of the issue")
    
    screenshot = models.ImageField(
        upload_to='screenshots/', 
        blank=True, 
        null=True,
        help_text="Optional screenshot evidence"
    )

    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    detected_by = models.CharField(max_length=100, default='unknown')

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
