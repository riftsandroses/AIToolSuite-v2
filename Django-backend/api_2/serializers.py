from rest_framework import serializers
from .models import ScanResultTC1, ScanSessionTC1, VulnerabilitySummaryTC1, ScanResultTC2, ScanSummaryTC2, TestCredentialTC2, ScanResultTC3, ScanSessionTC3, VulnerabilityTemplateTC3
from django.utils import timezone


class ScanInitiateSerializerTC1(serializers.Serializer):
    scan_id = serializers.IntegerField(min_value=1)
    scan_config = serializers.JSONField(required=False, default=dict)

class ScanResultSerializerTC1(serializers.ModelSerializer):
    progress_info = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanResultTC1
        fields = [
            'id', 'scan_id', 'api_id', 'api_name', 'api_method', 'api_url',
            'vulnerability_type', 'severity', 'status', 'title', 'description',
            'impact', 'recommendation', 'request_sent', 'response_received',
            'evidence', 'scan_started_at', 'scan_completed_at', 'progress_info'
        ]
        read_only_fields = ['id', 'scan_started_at', 'scan_completed_at', 'created_by']
    
    def get_progress_info(self, obj):
        return {
            'api_method': obj.api_method,
            'api_url': obj.api_url,
            'status': obj.status
        }

class ScanSessionSerializerTC1(serializers.ModelSerializer):
    progress_percentage = serializers.ReadOnlyField()
    
    class Meta:
        model = ScanSessionTC1
        fields = [
            'id', 'scan_id', 'total_apis', 'completed_apis', 'failed_apis',
            'vulnerabilities_found', 'status', 'started_at', 'completed_at',
            'progress_percentage', 'scan_config'
        ]
        read_only_fields = ['id', 'started_at', 'completed_at', 'created_by']

class VulnerabilitySummarySerializerTC1(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySummaryTC1
        fields = ['id', 'scan_id', 'vulnerability_type', 'severity', 'count', 'created_at']
        read_only_fields = ['id', 'created_at']

class ScanStatsSerializerTC1(serializers.Serializer):
    total_scans = serializers.IntegerField()
    active_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    medium_vulnerabilities = serializers.IntegerField()
    low_vulnerabilities = serializers.IntegerField()
    
class ScanHistorySerializerTC1(serializers.ModelSerializer):
    vulnerability_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanSessionTC1
        fields = [
            'id', 'scan_id', 'status', 'started_at', 'completed_at',
            'total_apis', 'completed_apis', 'failed_apis',
            'vulnerabilities_found', 'progress_percentage', 'vulnerability_summary'
        ]
    
    def get_vulnerability_summary(self, obj):
        summaries = VulnerabilitySummaryTC1.objects.filter(scan_id=obj.scan_id)
        return VulnerabilitySummarySerializerTC1(summaries, many=True).data

class ScanFilterSerializerTC1(serializers.Serializer):
    scan_id = serializers.IntegerField(required=False)
    vulnerability_type = serializers.ChoiceField(choices=ScanResultTC1.VULNERABILITY_TYPES, required=False)
    severity = serializers.ChoiceField(choices=ScanResultTC1.SEVERITY_LEVELS, required=False)
    status = serializers.ChoiceField(choices=ScanResultTC1.STATUS_CHOICES, required=False)
    api_method = serializers.CharField(required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)


class ScanInitiateTC2Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    
    def validate_scan_id(self, value):
        if value <= 0:
            raise serializers.ValidationError("scan_id must be a positive integer")
        return value


class ScanResultTC2Serializer(serializers.ModelSerializer):
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanResultTC2
        fields = [
            'id', 'scan_id', 'api_id', 'api_name', 'api_url', 'api_method',
            'scan_status', 'started_at', 'completed_at', 'duration',
            'vulnerability_found', 'vulnerability_type', 'severity',
            'total_attempts', 'successful_attempts', 'failed_attempts', 'rate_limited_attempts',
            'avg_response_time', 'status_codes_found', 'rate_limiting_detected',
            'account_lockout_detected', 'captcha_detected', 'exploit_successful',
            'exploit_details', 'recommendations', 'error_messages',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_duration(self, obj):
        if obj.completed_at and obj.started_at:
            return (obj.completed_at - obj.started_at).total_seconds()
        return None


class ScanResultFilterTC2Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField(required=False)
    scan_status = serializers.ChoiceField(
        choices=ScanResultTC2.SCAN_STATUS_CHOICES, 
        required=False
    )
    vulnerability_found = serializers.BooleanField(required=False)
    severity = serializers.ChoiceField(
        choices=ScanResultTC2.VULNERABILITY_SEVERITY_CHOICES, 
        required=False
    )
    api_method = serializers.CharField(required=False)
    exploit_successful = serializers.BooleanField(required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)


class ScanSummaryTC2Serializer(serializers.ModelSerializer):
    scan_duration = serializers.SerializerMethodField()
    vulnerability_rate = serializers.SerializerMethodField()
    completion_rate = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanSummaryTC2
        fields = [
            'id', 'scan_id', 'total_apis', 'completed_apis', 'pending_apis', 'failed_apis',
            'total_vulnerabilities', 'critical_vulnerabilities', 'high_vulnerabilities',
            'medium_vulnerabilities', 'low_vulnerabilities', 'scan_status',
            'started_at', 'completed_at', 'total_scan_time', 'scan_duration',
            'vulnerability_rate', 'completion_rate', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_scan_duration(self, obj):
        if obj.total_scan_time:
            return f"{obj.total_scan_time:.2f} seconds"
        return None
    
    def get_vulnerability_rate(self, obj):
        if obj.completed_apis > 0:
            return round((obj.total_vulnerabilities / obj.completed_apis) * 100, 2)
        return 0.0
    
    def get_completion_rate(self, obj):
        if obj.total_apis > 0:
            return round((obj.completed_apis / obj.total_apis) * 100, 2)
        return 0.0


class ScanStatusTC2Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    status = serializers.CharField()
    total_apis = serializers.IntegerField()
    completed_apis = serializers.IntegerField()
    pending_apis = serializers.IntegerField()
    failed_apis = serializers.IntegerField()
    progress_percentage = serializers.FloatField()
    estimated_time_remaining = serializers.CharField(allow_null=True)
    current_api = serializers.CharField(allow_null=True)
    started_at = serializers.DateTimeField()
    elapsed_time = serializers.CharField()


class ScanStatsTC2Serializer(serializers.Serializer):
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    total_apis_scanned = serializers.IntegerField()
    total_vulnerabilities_found = serializers.IntegerField()
    
    # Vulnerability breakdown
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    medium_vulnerabilities = serializers.IntegerField()
    low_vulnerabilities = serializers.IntegerField()
    
    # Recent activity
    scans_last_24h = serializers.IntegerField()
    scans_last_7d = serializers.IntegerField()
    scans_last_30d = serializers.IntegerField()
    
    # Performance metrics
    avg_scan_time = serializers.FloatField()
    avg_api_scan_time = serializers.FloatField()
    success_rate = serializers.FloatField()


class ScanHistoryTC2Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    scan_status = serializers.CharField()
    total_apis = serializers.IntegerField()
    vulnerabilities_found = serializers.IntegerField()
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField(allow_null=True)
    duration = serializers.CharField(allow_null=True)
    created_by = serializers.CharField(allow_null=True)


class TestCredentialTC2Serializer(serializers.ModelSerializer):
    class Meta:
        model = TestCredentialTC2
        fields = ['id', 'username', 'email', 'password', 'credential_type', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']


class VulnerabilitySummaryTC2Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    vulnerability_breakdown = serializers.DictField()
    most_common_vulnerability = serializers.CharField()
    apis_with_vulnerabilities = serializers.ListField()
    severity_distribution = serializers.DictField()
    recommendations = serializers.ListField()
    risk_score = serializers.FloatField()


class ScanInitiateSerializerTC3(serializers.Serializer):
    scan_id = serializers.IntegerField()
    vulnerability_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=['weak_password_policy']
    )
    config = serializers.JSONField(required=False, default=dict)


class ScanResultSerializerTC3(serializers.ModelSerializer):
    class Meta:
        model = ScanResultTC3
        fields = [
            'id', 'scan_id', 'api_id', 'vulnerability_type', 'severity', 'status',
            'api_name', 'api_method', 'api_url', 'title', 'description', 'impact',
            'recommendation', 'test_payload', 'test_response', 'exploit_successful',
            'evidence', 'screenshots', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScanResultListSerializerTC3(serializers.ModelSerializer):
    class Meta:
        model = ScanResultTC3
        fields = [
            'id', 'scan_id', 'api_id', 'vulnerability_type', 'severity', 'status',
            'api_name', 'api_method', 'api_url', 'title', 'exploit_successful',
            'created_at'
        ]


class ScanResultFilterSerializerTC3(serializers.Serializer):
    scan_id = serializers.IntegerField(required=False)
    vulnerability_type = serializers.CharField(required=False)
    severity = serializers.CharField(required=False)
    status = serializers.CharField(required=False)
    api_method = serializers.CharField(required=False)
    exploit_successful = serializers.BooleanField(required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)


class ScanSessionSerializerTC3(serializers.ModelSerializer):
    progress_percentage = serializers.ReadOnlyField()
    
    class Meta:
        model = ScanSessionTC3
        fields = [
            'id', 'scan_id', 'status', 'started_at', 'completed_at',
            'total_apis', 'apis_scanned', 'vulnerabilities_found',
            'progress_percentage', 'critical_count', 'high_count',
            'medium_count', 'low_count', 'info_count', 'errors'
        ]


class ScanStatsSerializerTC3(serializers.Serializer):
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    medium_vulnerabilities = serializers.IntegerField()
    low_vulnerabilities = serializers.IntegerField()
    recent_scans = ScanSessionSerializerTC3(many=True)


class VulnerabilitySummarySerializerTC3(serializers.Serializer):
    scan_id = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_count = serializers.IntegerField()
    high_count = serializers.IntegerField()
    medium_count = serializers.IntegerField()
    low_count = serializers.IntegerField()
    info_count = serializers.IntegerField()
    by_type = serializers.DictField()
    by_api = serializers.ListField()
    scan_status = serializers.CharField()
    scan_progress = serializers.FloatField()


class VulnerabilityTemplateSerializerTC3(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityTemplateTC3
        fields = '__all__'


class ScanHistorySerializerTC3(serializers.Serializer):
    scan_sessions = ScanSessionSerializerTC3(many=True)
    total_count = serializers.IntegerField()
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    total_pages = serializers.IntegerField()