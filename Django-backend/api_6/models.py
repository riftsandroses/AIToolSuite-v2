# models.py
from django.db import models
import uuid


class VulnerabilityScanTC1(models.Model):
    """Main scan model to track vulnerability scans"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.IntegerField(unique=True)  # Reference to api_orch scan
    name = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_apis = models.IntegerField(default=0)
    tested_apis = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_6_vulnerability_scan'
        ordering = ['-created_at']


class VulnerabilityTestTC1(models.Model):
    """Individual vulnerability test results"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'), 
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('vulnerable', 'Vulnerable'),
        ('not_vulnerable', 'Not Vulnerable'),
        ('error', 'Error'),
        ('timeout', 'Timeout'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(VulnerabilityScanTC1, on_delete=models.CASCADE, related_name='tests')
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_method = models.CharField(max_length=10)
    
    # Test details
    test_type = models.CharField(max_length=100)  # e.g., 'mass_account_creation'
    test_name = models.CharField(max_length=255)
    test_description = models.TextField()
    
    # Results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, null=True, blank=True)
    is_vulnerable = models.BooleanField(default=False)
    
    # Test execution data
    request_data = models.JSONField(default=dict, blank=True)
    response_data = models.JSONField(default=dict, blank=True)
    test_payload = models.JSONField(default=dict, blank=True)
    test_results = models.JSONField(default=dict, blank=True)
    
    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    execution_time_ms = models.IntegerField(null=True, blank=True)
    
    # Error handling
    error_message = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_6_vulnerability_test'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan', 'test_type']),
            models.Index(fields=['status', 'is_vulnerable']),
        ]


class MassAccountTestResultTC1(models.Model):
    """Specific results for mass account creation tests"""
    test = models.OneToOneField(VulnerabilityTestTC1, on_delete=models.CASCADE, related_name='mass_account_result')
    
    # Test parameters
    total_attempts = models.IntegerField(default=0)
    successful_accounts = models.IntegerField(default=0)
    failed_attempts = models.IntegerField(default=0)
    rate_limited_attempts = models.IntegerField(default=0)
    
    # Analysis results
    has_email_verification = models.BooleanField(default=False)
    has_phone_verification = models.BooleanField(default=False)
    has_captcha = models.BooleanField(default=False)
    has_rate_limiting = models.BooleanField(default=False)
    has_ip_restrictions = models.BooleanField(default=False)
    
    # Performance metrics
    average_response_time_ms = models.FloatField(null=True, blank=True)
    success_rate_percentage = models.FloatField(null=True, blank=True)
    accounts_per_minute = models.FloatField(null=True, blank=True)
    
    # Generated account data
    generated_accounts = models.JSONField(default=list, blank=True)
    failed_payloads = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_6_mass_account_test_result'


class ScanStatsTC1(models.Model):
    """Aggregated scan statistics"""
    scan = models.OneToOneField(VulnerabilityScanTC1, on_delete=models.CASCADE, related_name='stats')
    
    # Vulnerability counts by severity
    critical_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)
    info_vulnerabilities = models.IntegerField(default=0)
    
    # Test type counts
    mass_account_tests = models.IntegerField(default=0)
    mass_account_vulnerable = models.IntegerField(default=0)
    
    # Performance metrics
    total_requests_sent = models.IntegerField(default=0)
    average_response_time_ms = models.FloatField(null=True, blank=True)
    total_execution_time_seconds = models.IntegerField(null=True, blank=True)
    
    # Success rates
    test_success_rate = models.FloatField(null=True, blank=True)
    api_coverage_percentage = models.FloatField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_6_scan_stats'