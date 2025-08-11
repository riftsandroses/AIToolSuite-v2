from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import json

class UnboundedPaginationScan(models.Model):
    scan_id = models.CharField(max_length=255)
    api_url = models.TextField()
    method = models.CharField(max_length=10, default='GET')
    headers = models.JSONField()
    body = models.JSONField(null=True, blank=True)
    query_params = models.JSONField(null=True, blank=True)
    authorization = models.JSONField(null=True, blank=True)
    
    # Vulnerability details
    is_vulnerable = models.BooleanField(default=False)
    vulnerable_parameter = models.CharField(max_length=255, null=True, blank=True)
    test_value_used = models.IntegerField(null=True, blank=True)
    response_status_code = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    
    # ChatGPT analysis
    chatgpt_analysis = models.TextField(null=True, blank=True)
    identified_parameters = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'unbounded_pagination_scans'

class RateLimitScan(models.Model):
    """Model to store rate limiting scan results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    scan_id = models.IntegerField(help_text="Original scan ID from api_orch")
    api_id = models.IntegerField(help_text="API ID from api_orch_postmanapi table")
    api_name = models.CharField(max_length=255)
    api_url = models.URLField(max_length=1000)
    method = models.CharField(max_length=10)
    
    # Scan results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    is_vulnerable = models.BooleanField(default=False)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, null=True, blank=True)
    
    # Rate limiting details
    requests_sent = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    rate_limit_detected = models.BooleanField(default=False)
    rate_limit_threshold = models.IntegerField(null=True, blank=True)
    
    # Response analysis
    response_codes = models.JSONField(default=dict, help_text="Distribution of HTTP response codes")
    response_times = models.JSONField(default=list, help_text="List of response times in ms")
    rate_limit_headers = models.JSONField(default=dict, help_text="Rate limiting headers found")
    
    # Vulnerability details
    vulnerability_description = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    
    # Metadata
    scan_started_at = models.DateTimeField(auto_now_add=True)
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'api4_rate_limit_scans'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['status']),
            models.Index(fields=['is_vulnerable']),
        ]

class ScanLog(models.Model):
    """Model to store detailed scan logs"""
    LOG_LEVELS = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('debug', 'Debug'),
    ]
    
    scan = models.ForeignKey(RateLimitScan, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LOG_LEVELS)
    message = models.TextField()
    request_number = models.IntegerField(null=True, blank=True)
    response_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True, help_text="Response time in seconds")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api4_scan_logs'
        ordering = ['-timestamp']

class FileUploadScanResult(models.Model):
    VULNERABILITY_STATUS = [
        ('safe', 'Safe'),
        ('vulnerable', 'Vulnerable'),
        ('suspicious', 'Suspicious'),
        ('error', 'Error'),
    ]
    
    UPLOAD_TYPE = [
        ('webshell', 'Webshell Upload'),
        ('large_file', 'Large File Upload'),
        ('unrestricted', 'Unrestricted File Type'),
        ('mixed', 'Multiple Issues'),
    ]
    
    scan_id = models.IntegerField()
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.URLField(max_length=500)
    api_method = models.CharField(max_length=10)
    
    # Scan results
    status = models.CharField(max_length=20, choices=VULNERABILITY_STATUS, default='safe')
    vulnerability_type = models.CharField(max_length=20, choices=UPLOAD_TYPE, null=True, blank=True)
    
    # Test results
    accepts_file_upload = models.BooleanField(default=False)
    webshell_upload_success = models.BooleanField(default=False)
    large_file_upload_success = models.BooleanField(default=False)
    unrestricted_file_types = models.BooleanField(default=False)
    
    # Details
    response_status_code = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body_snippet = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    # File upload details
    uploaded_files = models.JSONField(default=list, blank=True)  # List of successfully uploaded files
    rejected_files = models.JSONField(default=list, blank=True)  # List of rejected files
    
    # Timing and metadata
    scan_duration = models.FloatField(null=True, blank=True)  # in seconds
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'file_upload_scan_results'
        unique_together = ['scan_id', 'api_id']
        
    def __str__(self):
        return f"Scan {self.scan_id} - API {self.api_name} - {self.status}"


class FileUploadTest(models.Model):
    """Track individual file upload tests"""
    scan_result = models.ForeignKey(FileUploadScanResult, on_delete=models.CASCADE, related_name='upload_tests')
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)
    file_size = models.BigIntegerField()  # in bytes
    test_type = models.CharField(max_length=20, choices=FileUploadScanResult.UPLOAD_TYPE)
    
    upload_success = models.BooleanField(default=False)
    response_status = models.IntegerField(null=True, blank=True)
    response_message = models.TextField(blank=True)
    upload_location = models.URLField(blank=True)  # Where the file was uploaded if successful
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'file_upload_tests'


class ScanSession(models.Model):
    """Track overall scan sessions"""
    scan_id = models.IntegerField(unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    total_apis = models.IntegerField(default=0)
    completed_apis = models.IntegerField(default=0)
    vulnerable_apis = models.IntegerField(default=0)
    
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='pending')
    
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'scan_sessions'
        
    def __str__(self):
        return f"Scan Session {self.scan_id} - {self.status}"

class AsyncTestResult(models.Model):
    scan_id = models.IntegerField()
    api_name = models.CharField(max_length=255)
    url = models.URLField()
    method = models.CharField(max_length=10)
    status_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    is_success = models.BooleanField(default=False)
    error_message = models.TextField(null=True, blank=True)
    request_details = models.JSONField(default=dict)
    response_details = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_4_asynctestresults'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['api_name']),
            models.Index(fields=['is_success']),
        ]

    def __str__(self):
        return f"{self.api_name} - {self.status_code or 'Error'}"

class FileDownloadTest(models.Model):
    scan_id = models.IntegerField()
    api_id = models.IntegerField()
    api_name = models.CharField(max_length=255)
    url = models.URLField()
    is_vulnerable = models.BooleanField(default=False)
    success_rate = models.FloatField(default=0.0)
    test_count = models.IntegerField(default=0)
    success_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    details = models.JSONField(default=dict)

    class Meta:
        db_table = 'api_4_filedownload_tests'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['api_id']),
            models.Index(fields=['is_vulnerable']),
        ]

class ScanHistory(models.Model):
    scan_id = models.IntegerField(unique=True)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_apis = models.IntegerField(default=0)
    tested_apis = models.IntegerField(default=0)
    vulnerable_apis = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='pending')
    logs = models.TextField(blank=True)

    class Meta:
        db_table = 'api_4_scan_history'

class ScanStats(models.Model):
    scan_id = models.IntegerField(unique=True)
    total_tests = models.IntegerField(default=0)
    total_vulnerabilities = models.IntegerField(default=0)
    avg_success_rate = models.FloatField(default=0.0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'api_4_scan_stats'