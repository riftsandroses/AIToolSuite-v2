from rest_framework import serializers
from .models import UnboundedPaginationScan, RateLimitScan, ScanLog, FileUploadScanResult, FileUploadTest, ScanSession, AsyncTestResult, FileDownloadTest, ScanHistory, ScanStats

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

class FileUploadTestSerializer(serializers.ModelSerializer):
    """Serializer for individual file upload tests"""
    
    class Meta:
        model = FileUploadTest
        fields = [
            'id', 'file_name', 'file_type', 'file_size', 'test_type',
            'upload_success', 'response_status', 'response_message',
            'upload_location', 'created_at'
        ]


class FileUploadScanResultSerializer(serializers.ModelSerializer):
    """Serializer for file upload scan results"""
    upload_tests = FileUploadTestSerializer(many=True, read_only=True)
    vulnerability_severity = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    
    class Meta:
        model = FileUploadScanResult
        fields = [
            'id', 'scan_id', 'api_id', 'api_name', 'api_url', 'api_method',
            'status', 'vulnerability_type', 'accepts_file_upload',
            'webshell_upload_success', 'large_file_upload_success',
            'unrestricted_file_types', 'response_status_code',
            'response_headers', 'response_body_snippet', 'error_message',
            'uploaded_files', 'rejected_files', 'scan_duration',
            'created_at', 'updated_at', 'upload_tests',
            'vulnerability_severity', 'risk_score'
        ]
    
    def get_vulnerability_severity(self, obj):
        """Calculate vulnerability severity based on findings"""
        if obj.status != 'vulnerable':
            return 'none'
        
        severity_score = 0
        
        if obj.webshell_upload_success:
            severity_score += 10  # Critical
        if obj.large_file_upload_success:
            severity_score += 5   # Medium
        if obj.unrestricted_file_types:
            severity_score += 3   # Low to Medium
        
        if severity_score >= 10:
            return 'critical'
        elif severity_score >= 5:
            return 'high'
        elif severity_score >= 3:
            return 'medium'
        else:
            return 'low'
    
    def get_risk_score(self, obj):
        """Calculate numerical risk score (0-100)"""
        if obj.status != 'vulnerable':
            return 0
        
        score = 0
        
        # Webshell upload is most critical
        if obj.webshell_upload_success:
            score += 70
        
        # Large file upload can cause DoS
        if obj.large_file_upload_success:
            score += 20
        
        # Unrestricted file types
        if obj.unrestricted_file_types:
            score += 10
        
        return min(score, 100)  # Cap at 100


class ScanSessionSerializer(serializers.ModelSerializer):
    """Serializer for scan sessions"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    duration = serializers.SerializerMethodField()
    progress_percentage = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanSession
        fields = [
            'id', 'scan_id', 'user_email', 'total_apis', 'completed_apis',
            'vulnerable_apis', 'status', 'started_at', 'completed_at',
            'duration', 'progress_percentage'
        ]
    
    def get_duration(self, obj):
        """Calculate scan duration in seconds"""
        if obj.completed_at and obj.started_at:
            return (obj.completed_at - obj.started_at).total_seconds()
        return None
    
    def get_progress_percentage(self, obj):
        """Calculate progress percentage"""
        if obj.total_apis == 0:
            return 0
        return round((obj.completed_apis / obj.total_apis) * 100, 2)


class ScanStatsSerializerTC3(serializers.Serializer):
    """Serializer for scan statistics"""
    scan_info = ScanSessionSerializer()
    vulnerability_summary = serializers.DictField()
    vulnerability_types = serializers.DictField()
    upload_capabilities = serializers.DictField()
    top_vulnerable_apis = FileUploadScanResultSerializer(many=True)


class VulnerabilityReportSerializer(serializers.Serializer):
    """Serializer for detailed vulnerability reports"""
    scan_id = serializers.IntegerField()
    generated_at = serializers.DateTimeField()
    total_apis_tested = serializers.IntegerField()
    vulnerable_apis_count = serializers.IntegerField()
    
    # Vulnerability breakdown
    webshell_vulnerabilities = serializers.IntegerField()
    large_file_vulnerabilities = serializers.IntegerField()
    unrestricted_file_vulnerabilities = serializers.IntegerField()
    
    # Risk assessment
    critical_risks = serializers.IntegerField()
    high_risks = serializers.IntegerField()
    medium_risks = serializers.IntegerField()
    low_risks = serializers.IntegerField()
    
    # Detailed results
    vulnerable_apis = FileUploadScanResultSerializer(many=True)
    
    # Recommendations
    recommendations = serializers.ListField(child=serializers.CharField())


class ScanComparisonSerializer(serializers.Serializer):
    """Serializer for comparing two scans"""
    original_scan_id = serializers.IntegerField()
    comparison_scan_id = serializers.IntegerField()
    
    original_stats = serializers.DictField()
    comparison_stats = serializers.DictField()
    
    # Changes
    newly_vulnerable = FileUploadScanResultSerializer(many=True)
    fixed_vulnerabilities = FileUploadScanResultSerializer(many=True)
    still_vulnerable = FileUploadScanResultSerializer(many=True)
    
    improvement_percentage = serializers.FloatField()


class ApiEndpointAnalysisSerializer(serializers.Serializer):
    """Serializer for API endpoint analysis"""
    api_id = serializers.IntegerField()
    api_name = serializers.CharField()
    api_url = serializers.URLField()
    method = serializers.CharField()
    
    # Analysis results
    likely_file_upload = serializers.BooleanField()
    risk_indicators = serializers.ListField(child=serializers.CharField())
    recommended_tests = serializers.ListField(child=serializers.CharField())
    
    # Historical data if available
    previous_scan_results = FileUploadScanResultSerializer(many=True)


class AsyncTestResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AsyncTestResult
        fields = '__all__'
        read_only_fields = ('created_at',)

class ScanInputSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField(required=True)
    concurrency = serializers.IntegerField(default=10, min_value=1, max_value=100)
    request_count = serializers.IntegerField(default=10, min_value=1, max_value=1000)

class FileDownloadTestSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileDownloadTest
        fields = '__all__'

class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = '__all__'

class ScanStatsSerializerTC5(serializers.ModelSerializer):
    class Meta:
        model = ScanStats
        fields = '__all__'