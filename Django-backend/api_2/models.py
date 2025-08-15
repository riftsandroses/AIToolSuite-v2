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