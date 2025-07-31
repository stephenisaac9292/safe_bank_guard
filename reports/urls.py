from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PhishingReportViewSet
from .views import PhishingReportViewSet, CheckPhishingAPIView


router = DefaultRouter()
router.register(r'reports', PhishingReportViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('check-domain/', CheckPhishingAPIView.as_view(), name='check-domain'),
]


