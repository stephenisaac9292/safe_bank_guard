from django.urls import path
from . import views

urlpatterns = [

    path('telemetry/', views.TelemetryAPIView.as_view(), name='telemetry'),
    path('phish-report/', views.PhishReportAPIView.as_view(), name='phish-report'), 
    path('banks/register-webhook/', views.BankWebhookRegisterAPIView.as_view(), name="bank-webhook-register"),
]


