from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import uuid

class CORSScanResultTC1(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('vulnerable', 'Vulnerable'),
        ('not_vulnerable', 'Not Vulnerable'),
        ('error', 'Error'),
        ('timeout', 'Timeout'),
    ]

    scan_id = models.IntegerField(db_index=True)
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.URLField(max_length=500)
    api_method = models.CharField(max_length=10)
    
    # CORS Test Results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, null=True, blank=True)
    
    # Response Headers
    access_control_allow_origin = models.TextField(null=True, blank=True)
    access_control_allow_credentials = models.BooleanField(null=True)
    access_control_allow_headers = models.TextField(null=True, blank=True)
    access_control_allow_methods = models.TextField(null=True, blank=True)
    access_control_max_age = models.CharField(max_length=50, null=True, blank=True)
    
    # Test Details
    origin_tested = models.CharField(max_length=255, default='https://evil.example')
    preflight_response_status = models.IntegerField(null=True, blank=True)
    actual_request_status = models.IntegerField(null=True, blank=True)
    
    # Vulnerability Details
    vulnerability_description = models.TextField(blank=True)
    exploit_poc = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    
    # Metadata
    response_time_ms = models.FloatField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    raw_response_headers = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'cors_scan_results'
        indexes = [
            models.Index(fields=['scan_id', 'status']),
            models.Index(fields=['scan_id', 'severity']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"CORS Scan {self.scan_id} - {self.api_name} ({self.status})"


class CORSScanSessionTC1(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    scan_id = models.IntegerField(unique=True, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    total_apis = models.IntegerField(default=0)
    scanned_apis = models.IntegerField(default=0)
    vulnerable_apis = models.IntegerField(default=0)
    
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Summary stats
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'cors_scan_sessions'

    def __str__(self):
        return f"CORS Scan Session {self.scan_id} ({self.status})"


class ScanTC2(models.Model):
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.IntegerField()  # Reference to the original scan from api_orch
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_apis = models.IntegerField(default=0)
    scanned_apis = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'api_8_scan_tc2'
        ordering = ['-started_at']

class VulnerabilityTC2(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('fixed', 'Fixed'),
        ('false_positive', 'False Positive'),
        ('accepted_risk', 'Accepted Risk'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanTC2, on_delete=models.CASCADE, related_name='vulnerabilities')
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_method = models.CharField(max_length=10)
    
    vulnerability_type = models.CharField(max_length=100, default='TLS/Transport Security')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    
    # TLS/Security specific fields
    supports_http = models.BooleanField(default=False)
    supports_https = models.BooleanField(default=False)
    tls_versions = models.JSONField(default=dict)  # {'supported': ['TLS1.2', 'TLS1.3'], 'deprecated': ['TLS1.0']}
    cipher_suites = models.JSONField(default=dict)
    certificate_info = models.JSONField(default=dict)
    security_headers = models.JSONField(default=dict)
    hsts_enabled = models.BooleanField(default=False)
    
    # Evidence and recommendations
    evidence = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    exploit_details = models.TextField(blank=True)
    
    # AI Analysis
    ai_analysis = models.TextField(blank=True)
    confidence_score = models.FloatField(default=0.0)  # 0.0 to 1.0
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_8_vulnerability_tc2'
        ordering = ['-created_at']

class ScanHistoryTC2(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanTC2, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=100)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'api_8_scan_history_tc2'
        ordering = ['-timestamp']

class ScanMetricsTC2(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(ScanTC2, on_delete=models.CASCADE, related_name='metrics')
    
    # Performance metrics
    total_duration_seconds = models.FloatField(default=0.0)
    average_response_time = models.FloatField(default=0.0)
    
    # Security findings breakdown
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    # TLS specific metrics
    http_only_apis = models.IntegerField(default=0)
    https_only_apis = models.IntegerField(default=0)
    mixed_protocol_apis = models.IntegerField(default=0)
    weak_tls_apis = models.IntegerField(default=0)
    missing_security_headers = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_8_scan_metrics_tc2'


class ScanTC3(models.Model):
    SCAN_STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled')
    ]
    
    id = models.AutoField(primary_key=True)
    scan_id = models.IntegerField(unique=True)
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='PENDING')
    total_apis = models.IntegerField(default=0)
    scanned_apis = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'api_8_scan_tc3'
        ordering = ['-started_at']

class VulnerabilityTC3(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'), 
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ]
    
    VULNERABILITY_TYPES = [
        ('VERBOSE_ERRORS', 'Verbose Errors'),
        ('DEBUG_MODE', 'Debug Mode'),
        ('STACK_TRACES', 'Stack Traces'),
        ('VERSION_DISCLOSURE', 'Version Disclosure'),
        ('FRAMEWORK_EXPOSURE', 'Framework Exposure')
    ]
    
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(ScanTC3, on_delete=models.CASCADE, related_name='vulnerabilities')
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_method = models.CharField(max_length=10)
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=500)
    description = models.TextField()
    evidence = models.JSONField()  # Store stack traces, headers, response body
    recommendation = models.TextField()
    cve_references = models.JSONField(default=list)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_8_vulnerability_tc3'
        ordering = ['-discovered_at']

class ScanHistoryTC3(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(ScanTC3, on_delete=models.CASCADE, related_name='history')
    api_id = models.IntegerField()
    api_name = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    response_time = models.FloatField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)
    tested_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_8_scan_history_tc3'
        ordering = ['-tested_at']

class ScanStatsTC3(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.OneToOneField(ScanTC3, on_delete=models.CASCADE, related_name='stats')
    total_requests = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    failed_requests = models.IntegerField(default=0)
    avg_response_time = models.FloatField(default=0.0)
    vulnerabilities_by_severity = models.JSONField(default=dict)
    vulnerabilities_by_type = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_8_scan_stats_tc3'