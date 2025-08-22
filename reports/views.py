from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.throttling import AnonRateThrottle
import logging
from .models import PhishingTelemetry, PhishingReport
from .serializers import TelemetrySerializer, PhishingReportSerializer
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.permissions import AllowAny


logger = logging.getLogger(__name__)

class TelemetryRateThrottle(AnonRateThrottle):
    rate = '1000/hour'

class TelemetryAPIView(CreateAPIView):
    queryset = PhishingTelemetry.objects.all()
    serializer_class = TelemetrySerializer
    throttle_classes = [TelemetryRateThrottle]

    def perform_create(self, serializer):
        # Save telemetry event
        telemetry = serializer.save()

        # Log metadata after save
        logger.info(
            f"Telemetry logged: {telemetry.event_type} from {telemetry.source}"
        )

        #trigger celery task
      
        return telemetry

    def create(self, request, *args, **kwargs):
        """
        Handles validation + response shaping.
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            print("Validation errors:", serializer.errors)  # shows in WSL terminal
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            telemetry = self.perform_create(serializer)
            return Response(
                {
                    'message': 'Telemetry logged',
                    'id': str(telemetry.id),
                    'event_type': telemetry.event_type,
                    'source': telemetry.source,
                },
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Failed to store telemetry: {str(e)}")
            return Response(
                {'error': 'Failed to store telemetry data'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        


class PhishReportAPIView(generics.CreateAPIView):
    """
    POST /api/phish-report
    Create a new phishing report
    """
    queryset = PhishingReport.objects.all()
    serializer_class = PhishingReportSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    throttle_classes = [TelemetryRateThrottle]
    permission_classes = [AllowAny]
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            report = serializer.save()
            logger.info(f"Report logged!")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Failed to log report: {e}")
            return Response({"error": "Could not save report."}, status=status.HTTP_400_BAD_REQUEST)





from rest_framework import generics, permissions
from .models import BankWebhook
from .serializers import BankWebhookSerializer

class BankWebhookRegisterAPIView(generics.CreateAPIView):
    queryset = BankWebhook.objects.all()
    serializer_class = BankWebhookSerializer
    permission_classes = [AllowAny]  # optional, can tighten later

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            bank_name = serializer.validated_data.get("bank_name")

            # Check duplicates
            if BankWebhook.objects.filter(bank_name=bank_name).exists():
                logger.warning(f"Duplicate registration attempt for {bank_name}")
                return Response(
                    {"status": "error", "message": f"{bank_name} is already registered"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Save
            bank_webhook = serializer.save()
            logger.info(f"Bank webhook registered successfully: {bank_webhook.bank_name}")

            return Response(
                {
                    "status": "success",
                    "message": "Bank webhook registered successfully",
                },
                status=status.HTTP_201_CREATED,
            )

        except serializers.ValidationError as e:
            logger.error(f"Validation error: {e}")
            return Response(
                {"status": "error", "message": e.detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            logger.exception("Unexpected error during bank webhook registration")
            return Response(
                {
                    "status": "error",
                    "message": "An unexpected error occurred. Please try again later.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

