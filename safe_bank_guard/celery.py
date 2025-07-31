import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'safe_bank_guard.settings')

app = Celery('safe_bank_guard')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
