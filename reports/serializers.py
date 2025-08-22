from rest_framework import serializers
from .models import PhishingTelemetry, PhishingReport, BankWebhook

from rest_framework import serializers
from .models import PhishingTelemetry


class TelemetrySerializer(serializers.ModelSerializer):
    class Meta:
        model = PhishingTelemetry
        fields = [
            'id',
            'event_time',
            'source',
            'schema_version',
            'event_type',
            'details',
            'normalized_summary',
            'enriched_flags',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        return Telemetry.objects.create(**validated_data)

    def validate_details(self, value):
        """
        Ensure the details payload is JSON and has at least a URL if event_type involves phishing.
        """
        if not isinstance(value, dict):
            raise serializers.ValidationError("Details must be a valid JSON object")
        
        # optional phishing-specific check
        if self.initial_data.get("event_type") in ["phish_click", "phish_report"]:
            if "url" not in value:
                raise serializers.ValidationError("Phishing-related events must include a 'url' in details")
            if not str(value["url"]).startswith("http"):
                raise serializers.ValidationError("URL must start with http or https")
        return value




class PhishingReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhishingReport
        fields = [
            'id',
            'url', 'screenshot','whois_data', 
            'host_data', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    
    def create(self, validated_data):
        return PhishingReport.objects.create(**validated_data)
        


class BankWebhookSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankWebhook
        fields = ["id", "bank_name", "webhook_url", "lifetimetoken", "created_at"]
        read_only_fields = ["id", "created_at"]


    def create(self, validated_data):
        return BankWebhook.objects.create(**validated_data)