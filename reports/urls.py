from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PhishingReportViewSet, CheckPhishingAPIView, TelemetryEventView, BankOptInView, ExtensionInitView

router = DefaultRouter()
router.register(r'reports', PhishingReportViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('check-domain/', CheckPhishingAPIView.as_view(), name='check-domain'),
    path('telemetry/', TelemetryEventView.as_view(), name='telemetry'),
    path('bank/opt-in/', BankOptInView.as_view(), name='bank-opt-in'),
    path('extension/init/', ExtensionInitView.as_view(), name='extension-init'),
]
 