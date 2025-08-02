import os
import logging
import base64
import requests
from urllib.parse import urlparse
from django.utils import timezone
from django.db.models import Count
from celery import shared_task

from .models import PhishingReport, TelemetryEvent
from .telemetry import log_report_counts


# === WHOIS & TAKEDOWN TASK ===

WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

TAKEDOWN_WEBHOOK_URL = "https://phish.report/api/report"

@shared_task(bind=True, max_retries=3)
def forward_report_to_services(self, report_id):
    try:
        report = PhishingReport.objects.get(id=report_id)
        url = report.url.strip().lower()
        domain = urlparse(url).netloc

        report.domain = domain
        report.save(update_fields=['domain'])

        # WHOIS lookup
        whois_params = {
            "apiKey": WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        whois_response = requests.get(WHOIS_API_URL, params=whois_params, timeout=10)
        whois_response.raise_for_status()
        whois_data = whois_response.json()

        whois_record = whois_data.get("WhoisRecord", {})
        registrar = whois_record.get("registrarName")
        created_date = whois_record.get("createdDate")
        expires_date = whois_record.get("expiresDate")

        report.whois_registrar = registrar
        report.whois_creation_date = created_date[:10] if created_date else None
        report.whois_expiry_date = expires_date[:10] if expires_date else None
        report.save(update_fields=['whois_registrar', 'whois_creation_date', 'whois_expiry_date'])

        # Enriched payload
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

        takedown_response = requests.post(TAKEDOWN_WEBHOOK_URL, json=payload, timeout=10)
        if takedown_response.status_code == 200:
            logging.info(f"✅ Report {report_id} sent successfully")
        else:
            logging.warning(f"⚠️ Report {report_id} takedown webhook failed: {takedown_response.status_code}")
            raise Exception("Takedown webhook error")

    except Exception as e:
        logging.error(f"❌ Error processing report {report_id}: {e}")
        self.retry(exc=e, countdown=10)


# === TELEMETRY LOGGING ===

@shared_task
def telemetry_log_hourly():
    log_report_counts()


# === VIRUSTOTAL TASK (for frontend-submitted telemetry) ===

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL_SUBMIT = "https://www.virustotal.com/api/v3/urls"

@shared_task
def push_unsent_telemetry_to_virustotal():
    unsent = TelemetryEvent.objects.filter(
        event_type='domain_submitted',
        sent_to_virustotal=False,
        metadata__has_key='domain'  # PostgreSQL only
    )

    for event in unsent:
        domain = event.metadata.get('domain')
        if not domain:
            continue

        url = f"http://{domain}"

        try:
            response = requests.post(
                VT_URL_SUBMIT,
                headers={"x-apikey": VT_API_KEY},
                data={"url": url},
                timeout=10
            )

            if response.status_code == 200:
                event.sent_to_virustotal = True
                event.save(update_fields=['sent_to_virustotal'])
                logging.info(f"✅ Telemetry domain submitted: {domain}")
            else:
                logging.warning(f"⚠️ VT failed for {domain}: {response.status_code}")

        except Exception as e:
            logging.error(f"❌ Error submitting {domain} to VT: {e}")
