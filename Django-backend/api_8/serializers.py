from rest_framework import serializers
from .models import CORSScanResultTC1, CORSScanSessionTC1


class CORSScanRequestTC1Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField(min_value=1)


class CORSScanResultTC1Serializer(serializers.ModelSerializer):
    class Meta:
        model = CORSScanResultTC1
        fields = [
            'id', 'scan_id', 'api_id', 'api_name', 'api_url', 'api_method',
            'status', 'severity', 'access_control_allow_origin',
            'access_control_allow_credentials', 'access_control_allow_headers',
            'access_control_allow_methods', 'access_control_max_age',
            'origin_tested', 'preflight_response_status', 'actual_request_status',
            'vulnerability_description', 'exploit_poc', 'remediation',
            'response_time_ms', 'error_message', 'raw_response_headers',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class CORSScanSessionTC1Serializer(serializers.ModelSerializer):
    progress_percentage = serializers.SerializerMethodField()
    duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = CORSScanSessionTC1
        fields = [
            'id', 'scan_id', 'status', 'total_apis', 'scanned_apis', 'vulnerable_apis',
            'started_at', 'completed_at', 'critical_count', 'high_count',
            'medium_count', 'low_count', 'info_count', 'error_message',
            'progress_percentage', 'duration_seconds', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_progress_percentage(self, obj):
        if obj.total_apis > 0:
            return round((obj.scanned_apis / obj.total_apis) * 100, 2)
        return 0

    def get_duration_seconds(self, obj):
        if obj.started_at and obj.completed_at:
            return (obj.completed_at - obj.started_at).total_seconds()
        elif obj.started_at:
            from django.utils import timezone
            return (timezone.now() - obj.started_at).total_seconds()
        return None


class VulnerabilitySummaryTC1Serializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    total_apis = serializers.IntegerField()
    vulnerable_apis = serializers.IntegerField()
    not_vulnerable_apis = serializers.IntegerField()
    error_apis = serializers.IntegerField()
    
    severity_breakdown = serializers.DictField()
    status_breakdown = serializers.DictField()
    
    most_common_vulnerabilities = serializers.ListField(child=serializers.DictField())
    risk_score = serializers.FloatField()
    scan_status = serializers.CharField()
    scan_duration = serializers.CharField()


class ScanStatsTC1Serializer(serializers.Serializer):
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    pending_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    
    total_apis_scanned = serializers.IntegerField()
    total_vulnerabilities_found = serializers.IntegerField()
    
    avg_vulnerabilities_per_scan = serializers.FloatField()
    avg_scan_duration_minutes = serializers.FloatField()
    
    recent_activity = serializers.ListField(child=serializers.DictField())