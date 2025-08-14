from rest_framework import serializers
from .models import CORSScanResultTC1, CORSScanSessionTC1, ScanTC2, VulnerabilityTC2, ScanHistoryTC2, ScanMetricsTC2


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


class ScanCreateSerializerTC2(serializers.Serializer):
    scan_id = serializers.IntegerField()

class VulnerabilitySerializerTC2(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityTC2
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

class VulnerabilitySummarySerializerTC2(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityTC2
        fields = ('id', 'api_name', 'api_url', 'title', 'severity', 'status', 
                 'vulnerability_type', 'confidence_score', 'created_at')

class ScanHistorySerializerTC2(serializers.ModelSerializer):
    class Meta:
        model = ScanHistoryTC2
        fields = '__all__'
        read_only_fields = ('id', 'timestamp')

class ScanMetricsSerializerTC2(serializers.ModelSerializer):
    class Meta:
        model = ScanMetricsTC2
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

class ScanSerializerTC2(serializers.ModelSerializer):
    vulnerabilities_count = serializers.SerializerMethodField()
    metrics = ScanMetricsSerializerTC2(read_only=True)
    
    class Meta:
        model = ScanTC2
        fields = '__all__'
        read_only_fields = ('id', 'started_at', 'completed_at', 'created_by')
    
    def get_vulnerabilities_count(self, obj):
        return obj.vulnerabilities.count()

class ScanStatusSerializerTC2(serializers.ModelSerializer):
    progress_percentage = serializers.SerializerMethodField()
    estimated_completion = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanTC2
        fields = ('id', 'status', 'started_at', 'completed_at', 'total_apis', 
                 'scanned_apis', 'vulnerabilities_found', 'progress_percentage',
                 'estimated_completion')
    
    def get_progress_percentage(self, obj):
        if obj.total_apis == 0:
            return 0
        return round((obj.scanned_apis / obj.total_apis) * 100, 2)
    
    def get_estimated_completion(self, obj):
        # Simple estimation based on current progress
        if obj.status in ['completed', 'failed', 'cancelled']:
            return None
        if obj.scanned_apis == 0:
            return None
        
        import datetime
        from django.utils import timezone
        
        elapsed = timezone.now() - obj.started_at
        if obj.scanned_apis > 0:
            avg_time_per_api = elapsed.total_seconds() / obj.scanned_apis
            remaining_apis = obj.total_apis - obj.scanned_apis
            estimated_seconds = remaining_apis * avg_time_per_api
            return obj.started_at + datetime.timedelta(seconds=elapsed.total_seconds() + estimated_seconds)
        
        return None

class ScanStatsSerializerTC2(serializers.Serializer):
    total_scans = serializers.IntegerField()
    active_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_vulnerabilities = serializers.IntegerField()
    high_vulnerabilities = serializers.IntegerField()
    medium_vulnerabilities = serializers.IntegerField()
    low_vulnerabilities = serializers.IntegerField()
    average_scan_duration = serializers.FloatField()
    most_common_vulnerabilities = serializers.ListField(child=serializers.DictField())
    vulnerability_trends = serializers.DictField()

class VulnerabilityFilterSerializerTC2(serializers.Serializer):
    severity = serializers.MultipleChoiceField(
        choices=VulnerabilityTC2.SEVERITY_CHOICES,
        required=False
    )
    status = serializers.MultipleChoiceField(
        choices=VulnerabilityTC2.STATUS_CHOICES,
        required=False
    )
    api_method = serializers.CharField(required=False)
    api_url_contains = serializers.CharField(required=False)
    confidence_score_min = serializers.FloatField(min_value=0.0, max_value=1.0, required=False)
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)
    has_exploit = serializers.BooleanField(required=False)
    
class ScanResultsSerializerTC2(serializers.Serializer):
    scan = ScanSerializerTC2()
    vulnerabilities = VulnerabilitySerializerTC2(many=True)
    total_vulnerabilities = serializers.IntegerField()
    filtered_count = serializers.IntegerField()
    filters_applied = serializers.DictField()