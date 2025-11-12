# models.py
from django.db import models
import uuid
from django.contrib.auth.models import User
import json
from django.utils import timezone


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


class ScanTC3(models.Model):
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    VULNERABILITY_SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.IntegerField(db_index=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='api6_scantc3_scans')
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    total_apis = models.IntegerField(default=0)
    processed_apis = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api6_scan_tc3'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan_id', 'status']),
            models.Index(fields=['created_at']),
        ]


class VulnerabilityTC3(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    VULNERABILITY_TYPES = [
        ('coupon_bruteforce', 'Coupon Brute Force'),
        ('promo_code_abuse', 'Promo Code Abuse'),
        ('rate_limit_bypass', 'Rate Limit Bypass'),
        ('code_reuse', 'Code Reuse'),
        ('code_stacking', 'Code Stacking'),
        ('weak_validation', 'Weak Validation'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanTC3, on_delete=models.CASCADE, related_name='vulnerabilities')
    api_id = models.IntegerField()
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    impact = models.TextField()
    remediation = models.TextField()
    evidence = models.JSONField(default=dict)
    cwe_id = models.CharField(max_length=20, null=True, blank=True)
    owasp_category = models.CharField(max_length=100, null=True, blank=True)
    confidence_score = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api6_vulnerability_tc3'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['vulnerability_type']),
            models.Index(fields=['api_id']),
        ]


class ScanResultTC3(models.Model):
    TEST_STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('error', 'Error'),
        ('skipped', 'Skipped'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanTC3, on_delete=models.CASCADE, related_name='results')
    api_id = models.IntegerField()
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_method = models.CharField(max_length=10)
    test_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=TEST_STATUS_CHOICES)
    response_time = models.FloatField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    request_data = models.JSONField(default=dict)
    response_data = models.JSONField(default=dict)
    findings = models.JSONField(default=dict)
    error_message = models.TextField(null=True, blank=True)
    tested_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api6_scan_result_tc3'
        ordering = ['-tested_at']
        indexes = [
            models.Index(fields=['scan', 'status']),
            models.Index(fields=['api_id']),
            models.Index(fields=['test_type']),
        ]


class CouponTestCaseTC3(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField()
    test_patterns = models.JSONField(default=list)  # List of coupon patterns to test
    expected_behaviors = models.JSONField(default=dict)
    severity_mapping = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api6_coupon_test_case_tc3'
        ordering = ['name']


class ScanConfigTC3(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.OneToOneField(ScanTC3, on_delete=models.CASCADE, related_name='config')
    max_requests_per_second = models.IntegerField(default=2)
    timeout_seconds = models.IntegerField(default=30)
    retry_attempts = models.IntegerField(default=3)
    enable_ai_analysis = models.BooleanField(default=True)
    ai_model = models.CharField(max_length=100, default='gpt-4o-mini')
    test_cases = models.ManyToManyField(CouponTestCaseTC3, blank=True)
    custom_wordlist = models.JSONField(default=list)
    excluded_endpoints = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api6_scan_config_tc3'