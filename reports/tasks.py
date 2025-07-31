from celery import shared_task
import requests
import logging
from django.core.mail import send_mail
from .models import PhishingReport
from urllib.parse import urlparse

from celery import shared_task
from .telemetry import log_report_counts

@shared_task(bind=True, max_retries=3)
def forward_report_to_services(self, report_id, url):
    try:
        # 1️⃣ Forward to PhishTank
        phishtank_response = requests.post(
            "http://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            timeout=5
        )
        logging.info(f"PhishTank response for report {report_id}: {phishtank_response.status_code}")

        # 2️⃣ Mock: Forward to Bank Webhook
        bank_domain = urlparse(url).netloc or "unknown-bank.com"
        bank_webhook = f"https://{bank_domain}/api/phishing-webhook"

        payload = {
            "phishing_url": url,
            "report_id": report_id,
            "detected_by": "SafeBank Guard",
        }

        response = requests.post(bank_webhook, json=payload, timeout=5)
        if 200 <= response.status_code < 300:
            logging.info(f"Forwarded report {report_id} to {bank_webhook}")
        else:
            logging.warning(f"Bank webhook error for report {report_id}: {response.status_code}")

        # 3️⃣ Email abuse@bank (for human teams)
        send_mail(
            subject='🚨 Phishing Attempt Detected',
            message=(
                f"A phishing site has been reported:\n\n"
                f"🔗 URL: {url}\n"
                f"🕵️‍♂️ Detected by: SafeBank Guard\n"
                f"📄 Report ID: {report_id}"
            ),
            from_email=None,  # uses DEFAULT_FROM_EMAIL
            recipient_list=[f'abuse@{bank_domain}'],
            fail_silently=False,
        )
        logging.info(f"Abuse email sent to abuse@{bank_domain} for report {report_id}")

    except Exception as e:
        logging.error(f"Error forwarding phishing report {report_id}: {str(e)}")
        self.retry(exc=e, countdown=10)





@shared_task
def telemetry_log_hourly():
    log_report_counts()
