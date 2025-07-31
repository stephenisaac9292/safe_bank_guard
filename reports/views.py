from rest_framework import viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from .models import PhishingReport
from .serializers import PhishingReportSerializer
from .tasks import forward_report_to_services  # ✅ Example Celery task
from rest_framework.views import APIView
from rest_framework.response import Response 

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

        # ✅ Hash IP for privacy
        import hashlib
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()

        # ✅ Save report
        report = serializer.save(
            ip_address=hashed_ip,
            user_agent=user_agent
        )

        # ✅ Fire async task (Celery)
        forward_report_to_services.delay(report.id, report.url)




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
