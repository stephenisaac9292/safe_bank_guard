import re
import hashlib
from rest_framework import serializers
from .models import PhishingReport, TelemetryEvent, Bank
from urllib.parse import urlparse


class PhishingReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhishingReport
        fields = ['id','url', 'description', 'screenshot', 'created_at']
        read_only_fields = ['id','created_at']

    def validate_description(self, value):
        clean = value.strip()
        clean = re.sub(r'[\w\.-]+@[\w\.-]+', '[email removed]', clean)
        clean = re.sub(r'(\+?\d[\d\s\-\(\)]{7,})', '[phone removed]', clean)
        clean = re.sub(r'\b\d{4,16}\b', '[number removed]', clean)
        return clean[:500]

    def validate_url(self, value):
        if "localhost" in value or "127.0.0.1" in value:
            raise serializers.ValidationError("Invalid URL: localhost not allowed.")
        return value

    def create(self, validated_data):

        #Get metadata passed through serializer context from views 
        ip = self.context.get('ip')
        user_agent = self.context.get('user_agent')
        extension_version = self.context.get('extension_version')

        # Create the report object in the database 

        report = PhishingReport.objects.create(
            **validated_data,
            ip_address=ip,
            user_agent=user_agent,
            extension_version=extension_version
        )
        return report



class TelemetryEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = TelemetryEvent
        fields = ['id', 'event_type', 'timestamp', 'metadata', 'sent_to_virustotal']
        read_only_fields = ['id', 'timestamp', 'sent_to_virustotal']


class BankOptInSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bank
        fields = ['bank_name', 'targeted_domains', 'webhook_url', 'auth_token', 'is_opted_in']

    def validate_webhook_url(self, value):
        parsed = urlparse(value)
        if parsed.scheme != 'https':
            raise serializers.ValidationError("Webhook URL must use HTTPS.")
        return value

    def validate_targeted_domains(self, value):
        if not value:
            raise serializers.ValidationError("At least one domain is required.")
        return [v.lower().strip() for v in value]


class ExtensionInitSerializer(serializers.Serializer):
    device_id = serializers.CharField(max_length=128)
    version = serializers.CharField(max_length=32)
    platform = serializers.ChoiceField(choices=["windows", "macos", "linux", "android", "ios", "unknown"])
