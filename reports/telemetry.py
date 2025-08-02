from django.utils import timezone
from .models import PhishingReport, TelemetryEvent


def log_report_counts():
    now = timezone.now()
    last_hour = now - timezone.timedelta(hours=1)
    count = PhishingReport.objects.filter(created_at__gte=last_hour).count()

    # Log as telemetry
    TelemetryEvent.objects.create(
        event_type='report_volume',
        timestamp=now,
        metadata={
            'count': count,
            'time_window': 'last_1_hour',
            'source': 'telemetry_log_hourly'
        }
    )

    print(f"[TELEMETRY] {count} reports submitted in the last hour - {now.isoformat()}")
