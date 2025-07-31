from django.utils import timezone
from .models import PhishingReport

def log_report_counts():
    now = timezone.now()
    last_hour = now - timezone.timedelta(hours=1)
    count = PhishingReport.objects.filter(created_at__gte=last_hour).count()

    print(f"[TELEMETRY] {count} reports submitted in the last hour - {now.isoformat()}")
