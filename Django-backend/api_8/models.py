from django.db import models
from django.utils import timezone


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