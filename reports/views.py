from rest_framework import viewsets, permissions, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import PhishingReport, TelemetryEvent, Bank 
from .serializers import PhishingReportSerializer, TelemetryEventSerializer, BankOptInSerializer
from .tasks import forward_report_to_services

import hashlib
from rest_framework import generics
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ExtensionInitSerializer

class PhishingReportViewSet(viewsets.ModelViewSet):
    queryset = PhishingReport.objects.all().order_by('-created_at')
    serializer_class = PhishingReportSerializer
    parser_classes = (MultiPartParser, FormParser)

    def get_permissions(self):
        # ✅ Allow anonymous POST, require admin for others
        if self.request.method == 'POST':
            return []
        return [permissions.IsAdminUser()]

    def perform_create(self, serializer):
        request = self.request
        ip = request.META.get('REMOTE_ADDR', '')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        extension_version = request.headers.get('X-Extension-Version', 'unknown')

        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()

        # Passig meta to serialiers
        serializer = PhishingReportSerializer(
            data=serializer.initial_data,
            context={
                'ip': hashed_ip,
                'user_agent': user_agent,
                'extension_version': extension_version
            }
        )

        serializer.is_valid(raise_exception=True)
        report = serializer.save()
        forward_report_to_services.delay(report.id)


class CheckPhishingAPIView(APIView):
    def get(self, request):
        url = request.query_params.get("url")
        if not url:
            return Response({"error": "Missing URL"}, status=status.HTTP_400_BAD_REQUEST)

        url = url.strip().lower()
        report = PhishingReport.objects.filter(url__icontains=url).order_by('-created_at').first()

        if report:
            return Response({
                "phishing": True,
                "message": "⚠️ This domain has been reported.",
                "reported_at": report.created_at,
            })

        return Response({
            "phishing": False,
            "message": "✅ This domain appears clean."
        })

class TelemetryEventView(APIView):
    def post(self, request):
        data = request.data
        event_type = data.get("event_type", "feature_used")
        metadata = data.get("metadata", {})

        TelemetryEvent.objects.create(
            event_type=event_type,
            metadata=metadata
        )
        return Response({"message": "Telemetry saved"}, status=status.HTTP_201_CREATED)

        # 👉 Trigger VirusTotal task if domain was submitted
        if event_type == "domain_submitted":
            push_unsent_telemetry_to_virustotal.delay()

class BankOptInView(generics.CreateAPIView):
    queryset = Bank.objects.all()
    serializer_class = BankOptInSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        bank_name = serializer.validated_data['bank_name']
        bank, created = Bank.objects.update_or_create(
            bank_name=bank_name,
            defaults=serializer.validated_data
        )

        return Response({
            "message": "Opt-in successful",
            "bank_id": bank.id,
            "is_new": created
        }, status=status.HTTP_201_CREATED)

class ExtensionInitView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ExtensionInitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh = RefreshToken.for_user(AnonymousUser())
        access_token = str(refresh.access_token)

        return Response({
            "access": access_token,
            "expires_in": 3600,
            "session_id": serializer.validated_data["device_id"]
        }, status=200)
