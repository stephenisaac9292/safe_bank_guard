import re
import hashlib
from rest_framework import serializers
from .models import PhishingReport

class PhishingReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhishingReport
        fields = ['id', 'url', 'description', 'screenshot', 'created_at']
        read_only_fields = ['id', 'created_at']

    def validate_description(self, value):
        # Sanitize PII (emails, phones, numbers)
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
        request = self.context.get('request')
        if request:
            ip = request.META.get('REMOTE_ADDR', '')
            hashed_ip = hashlib.sha256(ip.encode()).hexdigest()
            validated_data['ip_address'] = hashed_ip
            validated_data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
        return super().create(validated_data)
