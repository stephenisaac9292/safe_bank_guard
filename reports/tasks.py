import logging
import requests
from urllib.parse import urlparse
from celery import shared_task
from .models import PhishingReport
from .telemetry import log_report_counts

WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
WHOIS_API_KEY = "your_real_whois_api_key_here"  # <- put your real key

TAKEDOWN_WEBHOOK_URL = "https://phish.report/api/report"  # real endpoint you use

@shared_task(bind=True, max_retries=3)
def forward_report_to_services(self, report_id):
    try:
        report = PhishingReport.objects.get(id=report_id)
        url = report.url.strip().lower()

        # Extract domain from URL
        domain = urlparse(url).netloc
        report.domain = domain
        report.save(update_fields=['domain'])

        # Call WHOIS API for domain info
        whois_params = {
            "apiKey": WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        whois_response = requests.get(WHOIS_API_URL, params=whois_params, timeout=10)
        whois_response.raise_for_status()
        whois_data = whois_response.json()

        # Parse WHOIS fields (adjust based on actual response)
        whois_record = whois_data.get("WhoisRecord", {})
        registrar = whois_record.get("registrarName")
        created_date = whois_record.get("createdDate")
        expires_date = whois_record.get("expiresDate")

        # Save WHOIS info
        report.whois_registrar = registrar
        report.whois_creation_date = created_date[:10] if created_date else None
        report.whois_expiry_date = expires_date[:10] if expires_date else None
        report.save(update_fields=['whois_registrar', 'whois_creation_date', 'whois_expiry_date'])

        # Prepare enriched payload for takedown
        payload = {
            "url": url,
            "domain": domain,
            "whois": {
                "registrar": registrar,
                "creation_date": created_date,
                "expiry_date": expires_date,
            },
            "ip_address_hash": report.ip_address,
            "user_agent": report.user_agent,
            "extension_version": report.extension_version,
            "created_at": report.created_at.isoformat(),
        }

        # Send to takedown webhook
        takedown_response = requests.post(TAKEDOWN_WEBHOOK_URL, json=payload, timeout=10)
        if takedown_response.status_code == 200:
            logging.info(f"✅ Report {report_id} sent successfully")
        else:
            logging.warning(f"⚠️ Report {report_id} takedown webhook failed: {takedown_response.status_code}")
            raise Exception("Takedown webhook error")

    except Exception as e:
        logging.error(f"❌ Error processing report {report_id}: {e}")
        self.retry(exc=e, countdown=10)


@shared_task
def telemetry_log_hourly():
    log_report_counts()
