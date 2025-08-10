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