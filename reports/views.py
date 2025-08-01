from rest_framework import viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from .models import PhishingReport
from .serializers import PhishingReportSerializer
from .tasks import forward_report_to_services  # ✅ Example Celery task
from rest_framework.views import APIView
from rest_framework.response import Response 

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import PhishingReport
from .tasks import forward_report_to_services

from .serializers import TelemetryEventSerializer



class PhishingReportViewSet(viewsets.ModelViewSet):
    queryset = PhishingReport.objects.all().order_by('-created_at')
    serializer_class = PhishingReportSerializer
    parser_classes = (MultiPartParser, FormParser)  # allow file uploads

    def get_permissions(self):
        # ✅ Allow anonymous POST, require admin for everything else
        if self.request.method == 'POST':
            return []
        return [permissions.IsAdminUser()]  # 🔐 Admins only

    def perform_create(self, serializer):
        request = self.request
        ip = request.META.get('REMOTE_ADDR', '')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        extension_version = request.headers.get('X-Extension-Version', 'unknown')

        # ✅ Hash IP for privacy
        import hashlib
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()

        # ✅ Save report
        report = serializer.save(
            ip_address=hashed_ip,
            user_agent=user_agent,
            extension_version=extension_version
        )

        # ✅ Fire async task (Celery)
        forward_report_to_services.delay(report.id)




class CheckPhishingAPIView(APIView):
    def get(self, request):
        url = request.query_params.get("url")
        if not url:
            return Response({"error": "Missing URL"}, status=400)

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



class TelemetryEventAPIView(APIView):
    permission_classes = []  # open or add auth if needed

    def post(self, request):
        serializer = TelemetryEventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Telemetry event saved"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)