from django.db import models
from django.contrib.auth.models import User
import json

class ScanResultTC1(models.Model):
    VULNERABILITY_TYPES = [
        ('weak_auth', 'Missing or Weak Authentication'),
        ('broken_access', 'Broken Access Control'),
        ('injection', 'Injection Vulnerability'),
        ('data_exposure', 'Data Exposure'),
        ('other', 'Other')
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info')
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled')
    ]

    scan_id = models.IntegerField(db_index=True)
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=500)
    api_method = models.CharField(max_length=10)
    api_url = models.TextField()
    
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Vulnerability details
    title = models.CharField(max_length=500)
    description = models.TextField()
    impact = models.TextField()
    recommendation = models.TextField()
    
    # Technical details
    request_sent = models.TextField(blank=True, null=True)
    response_received = models.TextField(blank=True, null=True)
    evidence = models.TextField(blank=True, null=True)  # JSON field for proof
    
    # Metadata
    scan_started_at = models.DateTimeField(auto_now_add=True)
    scan_completed_at = models.DateTimeField(blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'api2_scan_results'
        indexes = [
            models.Index(fields=['scan_id', 'status']),
            models.Index(fields=['vulnerability_type', 'severity']),
            models.Index(fields=['created_by', 'scan_started_at']),
        ]

    def __str__(self):
        return f"Scan {self.scan_id} - {self.api_name} - {self.vulnerability_type}"

class ScanSessionTC1(models.Model):
    scan_id = models.IntegerField(unique=True, db_index=True)
    total_apis = models.IntegerField(default=0)
    completed_apis = models.IntegerField(default=0)
    failed_apis = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    
    status = models.CharField(max_length=20, choices=ScanResultTC1.STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Scan configuration
    scan_config = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'api2_scan_sessions'

    @property
    def progress_percentage(self):
        if self.total_apis == 0:
            return 0
        return round((self.completed_apis / self.total_apis) * 100, 2)

    def __str__(self):
        return f"Scan Session {self.scan_id} - {self.status}"

class VulnerabilitySummaryTC1(models.Model):
    scan_id = models.IntegerField(db_index=True)
    vulnerability_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api2_vulnerability_summary'
        unique_together = ['scan_id', 'vulnerability_type', 'severity']

    def __str__(self):
        return f"Scan {self.scan_id} - {self.vulnerability_type} - {self.severity}: {self.count}"

class ScanResultTC2(models.Model):
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    VULNERABILITY_SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    scan_id = models.IntegerField()
    api_id = models.IntegerField()  # References api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.TextField()
    api_method = models.CharField(max_length=10)
    
    # Scan metadata
    scan_status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Vulnerability findings
    vulnerability_found = models.BooleanField(default=False)
    vulnerability_type = models.CharField(max_length=100, default='Credential Stuffing / Brute Force')
    severity = models.CharField(max_length=20, choices=VULNERABILITY_SEVERITY_CHOICES, null=True, blank=True)
    
    # Test results
    total_attempts = models.IntegerField(default=0)
    successful_attempts = models.IntegerField(default=0)
    failed_attempts = models.IntegerField(default=0)
    rate_limited_attempts = models.IntegerField(default=0)
    
    # Response analysis
    avg_response_time = models.FloatField(null=True, blank=True)
    status_codes_found = models.JSONField(default=dict)  # {200: 5, 401: 45, 429: 0}
    rate_limiting_detected = models.BooleanField(default=False)
    account_lockout_detected = models.BooleanField(default=False)
    captcha_detected = models.BooleanField(default=False)
    
    # Detailed findings
    exploit_successful = models.BooleanField(default=False)
    exploit_details = models.TextField(null=True, blank=True)
    recommendations = models.TextField(null=True, blank=True)
    
    # Raw data
    test_credentials_used = models.JSONField(default=list)
    response_samples = models.JSONField(default=list)  # Sample responses for analysis
    error_messages = models.TextField(null=True, blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_2_scan_results'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['scan_status']),
            models.Index(fields=['vulnerability_found']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Scan {self.scan_id} - {self.api_name} ({self.scan_status})"


class ScanSummaryTC2(models.Model):
    scan_id = models.IntegerField(unique=True)
    total_apis = models.IntegerField(default=0)
    completed_apis = models.IntegerField(default=0)
    pending_apis = models.IntegerField(default=0)
    failed_apis = models.IntegerField(default=0)
    
    # Vulnerability stats
    total_vulnerabilities = models.IntegerField(default=0)
    critical_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)
    
    # Scan metadata
    scan_status = models.CharField(max_length=20, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_scan_time = models.FloatField(null=True, blank=True)  # in seconds
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_2_scan_summaries'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['scan_status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Scan Summary {self.scan_id} - {self.scan_status}"


class TestCredentialTC2(models.Model):
    """Predefined test credentials for brute force testing"""
    username = models.CharField(max_length=255)
    email = models.EmailField(null=True, blank=True)
    password = models.CharField(max_length=255)
    credential_type = models.CharField(max_length=50, default='common')  # common, weak, default
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_2_test_credentials'
    
    def __str__(self):
        return f"{self.username}:{self.password}"


class ScanResultTC3(models.Model):
    VULNERABILITY_CHOICES = [
        ('weak_password_policy', 'Weak or Default Password Policy'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting'),
        ('csrf', 'Cross-Site Request Forgery'),
        ('auth_bypass', 'Authentication Bypass'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    scan_id = models.IntegerField()
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # API Details
    api_name = models.CharField(max_length=255)
    api_method = models.CharField(max_length=10)
    api_url = models.TextField()
    
    # Vulnerability Details
    title = models.CharField(max_length=255)
    description = models.TextField()
    impact = models.TextField()
    recommendation = models.TextField()
    
    # Test Details
    test_payload = models.JSONField(default=dict)
    test_response = models.JSONField(default=dict)
    exploit_successful = models.BooleanField(default=False)
    
    # Evidence
    evidence = models.JSONField(default=dict)
    screenshots = models.JSONField(default=list)
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api2_scan_results_tc3'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['vulnerability_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.api_name} - {self.vulnerability_type} ({self.severity})"


class ScanSessionTC3(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    scan_id = models.IntegerField(unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Statistics
    total_apis = models.IntegerField(default=0)
    apis_scanned = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    
    # Configuration
    scan_config = models.JSONField(default=dict)
    
    # Results Summary
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    # Error tracking
    errors = models.JSONField(default=list)
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    class Meta:
        db_table = 'api2_scan_sessions_tc3'
    
    def __str__(self):
        return f"Scan {self.scan_id} - {self.status}"
    
    @property
    def progress_percentage(self):
        if self.total_apis == 0:
            return 0
        return round((self.apis_scanned / self.total_apis) * 100, 2)


class VulnerabilityTemplateTC3(models.Model):
    name = models.CharField(max_length=100, unique=True)
    vulnerability_type = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    description = models.TextField()
    impact = models.TextField()
    recommendation = models.TextField()
    test_payloads = models.JSONField(default=list)
    detection_patterns = models.JSONField(default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api2_vulnerability_templates'
    
    def __str__(self):
        return self.name


class JWTScanTC4(models.Model):
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    scan_id = models.IntegerField(unique=True)
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    total_apis = models.IntegerField(default=0)
    scanned_apis = models.IntegerField(default=0)
    vulnerable_apis = models.IntegerField(default=0)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    scan_duration = models.FloatField(null=True, blank=True)  # in seconds
    
    class Meta:
        db_table = 'jwt_scan_tc4'
        ordering = ['-created_at']


class JWTVulnerabilityTC4(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    VULNERABILITY_TYPES = [
        ('none_algorithm', 'None Algorithm'),
        ('weak_secret', 'Weak Secret'),
        ('algorithm_confusion', 'Algorithm Confusion'),
        ('payload_manipulation', 'Payload Manipulation'),
        ('expired_token_accepted', 'Expired Token Accepted'),
        ('malformed_token_accepted', 'Malformed Token Accepted'),
    ]
    
    scan = models.ForeignKey(JWTScanTC4, on_delete=models.CASCADE, related_name='vulnerabilities')
    api_id = models.IntegerField()  # Reference to api_orch_postmanapi.id
    api_name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_method = models.CharField(max_length=10)
    
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    is_vulnerable = models.BooleanField(default=False)
    
    original_token = models.TextField(null=True, blank=True)
    forged_token = models.TextField(null=True, blank=True)
    original_response_code = models.IntegerField(null=True, blank=True)
    forged_response_code = models.IntegerField(null=True, blank=True)
    
    original_response_body = models.TextField(null=True, blank=True)
    forged_response_body = models.TextField(null=True, blank=True)
    
    payload_changes = models.JSONField(default=dict)  # What was changed in payload
    exploitation_details = models.TextField(null=True, blank=True)
    ai_analysis = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'jwt_vulnerability_tc4'
        ordering = ['-created_at']
        unique_together = ['scan', 'api_id', 'vulnerability_type']


class JWTScanLogTC4(models.Model):
    LOG_LEVELS = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('debug', 'Debug'),
    ]
    
    scan = models.ForeignKey(JWTScanTC4, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LOG_LEVELS)
    message = models.TextField()
    api_id = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    additional_data = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'jwt_scan_log_tc4'
        ordering = ['-timestamp']


class JWTScanConfigTC4(models.Model):
    scan = models.OneToOneField(JWTScanTC4, on_delete=models.CASCADE, related_name='config')
    
    # Test configurations
    test_none_algorithm = models.BooleanField(default=True)
    test_weak_secrets = models.BooleanField(default=True)
    test_algorithm_confusion = models.BooleanField(default=True)
    test_payload_manipulation = models.BooleanField(default=True)
    test_expired_tokens = models.BooleanField(default=True)
    test_malformed_tokens = models.BooleanField(default=True)
    
    # Payload manipulation settings
    role_escalation_payloads = models.JSONField(default=list)  # [{"role": "admin"}, {"is_admin": true}]
    custom_payloads = models.JSONField(default=list)
    
    # Secret bruteforce list
    weak_secrets = models.JSONField(default=list)
    
    # Timeout settings
    request_timeout = models.IntegerField(default=30)  # seconds
    max_retries = models.IntegerField(default=3)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'jwt_scan_config_tc4'


class JWTTokenAnalysisTC4(models.Model):
    scan = models.ForeignKey(JWTScanTC4, on_delete=models.CASCADE, related_name='token_analyses')
    api_id = models.IntegerField()
    
    original_token = models.TextField()
    token_header = models.JSONField(default=dict)
    token_payload = models.JSONField(default=dict)
    token_signature = models.TextField(null=True, blank=True)
    
    algorithm = models.CharField(max_length=20, null=True, blank=True)
    issuer = models.CharField(max_length=255, null=True, blank=True)
    expiry = models.DateTimeField(null=True, blank=True)
    
    # AI Analysis
    ai_risk_assessment = models.TextField(null=True, blank=True)
    ai_recommendations = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'jwt_token_analysis_tc4'
        ordering = ['-created_at']