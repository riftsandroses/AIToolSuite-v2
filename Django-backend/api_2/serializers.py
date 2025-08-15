from rest_framework import serializers
from .models import ScanResultTC1, ScanSessionTC1, VulnerabilitySummaryTC1

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