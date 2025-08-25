# serializers.py
from rest_framework import serializers
from .models import (
    VulnerabilityScanTC1, VulnerabilityTestTC1, 
    MassAccountTestResultTC1, ScanStatsTC1
)


class ScanStartRequestSerializerTC1(serializers.Serializer):
    """Serializer for starting a vulnerability scan"""
    scan_id = serializers.IntegerField()
    scan_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    test_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=['mass_account_creation']
    )
    max_accounts_per_api = serializers.IntegerField(default=5, min_value=1, max_value=50)
    timeout_seconds = serializers.IntegerField(default=30, min_value=5, max_value=300)


class MassAccountTestResultSerializerTC1(serializers.ModelSerializer):
    """Serializer for mass account creation test results"""
    class Meta:
        model = MassAccountTestResultTC1
        fields = [
            'total_attempts', 'successful_accounts', 'failed_attempts', 
            'rate_limited_attempts', 'has_email_verification', 'has_phone_verification',
            'has_captcha', 'has_rate_limiting', 'has_ip_restrictions',
            'average_response_time_ms', 'success_rate_percentage', 
            'accounts_per_minute', 'generated_accounts', 'failed_payloads'
        ]


class VulnerabilityTestSerializerTC1(serializers.ModelSerializer):
    """Serializer for individual vulnerability tests"""
    mass_account_result = MassAccountTestResultSerializerTC1(read_only=True, required=False)
    
    class Meta:
        model = VulnerabilityTestTC1
        fields = [
            'id', 'api_id', 'api_name', 'api_url', 'api_method',
            'test_type', 'test_name', 'test_description', 'status', 
            'severity', 'is_vulnerable', 'request_data', 'response_data',
            'test_payload', 'test_results', 'started_at', 'completed_at',
            'execution_time_ms', 'error_message', 'created_at', 'updated_at',
            'mass_account_result'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScanStatsSerializerTC1(serializers.ModelSerializer):
    """Serializer for scan statistics"""
    vulnerability_breakdown = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanStatsTC1
        fields = [
            'critical_vulnerabilities', 'high_vulnerabilities', 'medium_vulnerabilities',
            'low_vulnerabilities', 'info_vulnerabilities', 'mass_account_tests',
            'mass_account_vulnerable', 'total_requests_sent', 'average_response_time_ms',
            'total_execution_time_seconds', 'test_success_rate', 'api_coverage_percentage',
            'vulnerability_breakdown', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_vulnerability_breakdown(self, obj):
        return {
            'critical': obj.critical_vulnerabilities,
            'high': obj.high_vulnerabilities,
            'medium': obj.medium_vulnerabilities,
            'low': obj.low_vulnerabilities,
            'info': obj.info_vulnerabilities,
        }


class VulnerabilityScanSerializerTC1(serializers.ModelSerializer):
    """Serializer for vulnerability scans"""
    tests = VulnerabilityTestSerializerTC1(many=True, read_only=True)
    stats = ScanStatsSerializerTC1(read_only=True, required=False)
    
    class Meta:
        model = VulnerabilityScanTC1
        fields = [
            'id', 'scan_id', 'name', 'status', 'started_at', 'completed_at',
            'total_apis', 'tested_apis', 'vulnerabilities_found',
            'created_at', 'updated_at', 'tests', 'stats'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class VulnerabilityScanListSerializerTC1(serializers.ModelSerializer):
    """Lightweight serializer for scan lists"""
    stats = ScanStatsSerializerTC1(read_only=True, required=False)
    
    class Meta:
        model = VulnerabilityScanTC1
        fields = [
            'id', 'scan_id', 'name', 'status', 'started_at', 'completed_at',
            'total_apis', 'tested_apis', 'vulnerabilities_found',
            'created_at', 'updated_at', 'stats'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class VulnerabilityTestFilterSerializerTC1(serializers.Serializer):
    """Serializer for filtering vulnerability tests"""
    scan_id = serializers.UUIDField(required=False)
    test_type = serializers.CharField(max_length=100, required=False)
    status = serializers.ChoiceField(
        choices=VulnerabilityTestTC1.STATUS_CHOICES, 
        required=False
    )
    severity = serializers.ChoiceField(
        choices=VulnerabilityTestTC1.SEVERITY_CHOICES,
        required=False
    )
    is_vulnerable = serializers.BooleanField(required=False)
    api_method = serializers.CharField(max_length=10, required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)


class VulnerabilitySummarySerializerTC1(serializers.Serializer):
    """Serializer for vulnerability summary"""
    total_scans = serializers.IntegerField()
    active_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    
    total_tests = serializers.IntegerField()
    vulnerable_tests = serializers.IntegerField()
    
    vulnerabilities_by_severity = serializers.DictField()
    vulnerabilities_by_type = serializers.DictField()
    
    top_vulnerable_apis = serializers.ListField()
    recent_scans = VulnerabilityScanListSerializerTC1(many=True)


class ScanHistorySerializerTC1(serializers.Serializer):
    """Serializer for scan history with pagination"""
    page = serializers.IntegerField(default=1, min_value=1)
    page_size = serializers.IntegerField(default=20, min_value=1, max_value=100)
    status = serializers.ChoiceField(
        choices=VulnerabilityScanTC1.STATUS_CHOICES,
        required=False
    )
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)