from rest_framework import serializers
from .models import UnboundedPaginationScan, RateLimitScan, ScanLog

class UnboundedPaginationScanSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=255)

class UnboundedPaginationResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnboundedPaginationScan
        fields = '__all__'

class ScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanLog
        fields = '__all__'

class RateLimitScanSerializer(serializers.ModelSerializer):
    logs = ScanLogSerializer(many=True, read_only=True)
    
    class Meta:
        model = RateLimitScan
        fields = '__all__'
        read_only_fields = ['scan_started_at', 'scan_completed_at', 'created_by']

class ScanRequestSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField(min_value=1)
    max_requests = serializers.IntegerField(default=100, min_value=1, max_value=1000)
    delay_between_requests = serializers.FloatField(default=0.1, min_value=0.0, max_value=5.0)
    timeout = serializers.IntegerField(default=30, min_value=1, max_value=300)

class ScanStatsSerializer(serializers.Serializer):
    total_scans = serializers.IntegerField()
    vulnerable_apis = serializers.IntegerField()
    scans_by_status = serializers.DictField()
    scans_by_severity = serializers.DictField()
    avg_response_time = serializers.FloatField()
    top_vulnerable_apis = serializers.ListField()
