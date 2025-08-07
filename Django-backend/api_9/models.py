# api_9/models.py
from django.db import models
from django.utils import timezone

class UnlistedEndpoints(models.Model):
    scan_id = models.CharField(max_length=100)
    endpoint_url = models.URLField()
    discovered_at = models.DateTimeField(auto_now_add=True)
    method = models.CharField(max_length=10, default='GET')
    status_code = models.IntegerField(null=True, blank=True)
    
    class Meta:
        db_table = 'api_9_unlisted_endpoints'
        unique_together = ('scan_id', 'endpoint_url')
    
    def __str__(self):
        return f"{self.scan_id} - {self.endpoint_url}"

class SubdomainDiscovery(models.Model):
    ENVIRONMENT_CHOICES = [
        ('unknown', 'Unknown'),
        ('dev', 'Development'),
        ('staging', 'Staging'),
        ('production', 'Production'),
    ]
    
    STATUS_CHOICES = [
        ('live', 'Live'),
        ('dead', 'Dead'),
    ]
    
    scan_id = models.CharField(max_length=100, db_index=True)
    base_url = models.URLField()
    subdomain = models.URLField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='live')
    environment_type = models.CharField(max_length=20, choices=ENVIRONMENT_CHOICES, default='unknown')
    discovered_at = models.DateTimeField(default=timezone.now)
    chatgpt_response = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'subdomain_discovery'
        unique_together = ['scan_id', 'subdomain']


class DocumentationEndpoint(models.Model):
    STATUS_CHOICES = [
        ('success', 'Success (200)'),
        ('forbidden', 'Forbidden (403)'),
        ('unauthorized', 'Unauthorized (401)'),
        ('other', 'Other'),
    ]
    
    DOC_TYPE_CHOICES = [
        ('swagger', 'Swagger/OpenAPI'),
        ('docs', 'Documentation'),
        ('api-docs', 'API Docs'),
        ('redoc', 'ReDoc'),
        ('openapi', 'OpenAPI Spec'),
        ('other', 'Other'),
    ]

    scan_id = models.CharField(max_length=100, db_index=True)
    base_url = models.URLField()
    endpoint_url = models.URLField()
    doc_type = models.CharField(max_length=20, choices=DOC_TYPE_CHOICES)
    status_code = models.IntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    response_content_type = models.CharField(max_length=100, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    scan_timestamp = models.DateTimeField(default=timezone.now)
    response_preview = models.TextField(blank=True, help_text="First 1000 chars of response")
    
    class Meta:
        db_table = 'api_9_documentation_endpoint'
        unique_together = ['scan_id', 'endpoint_url']
        ordering = ['-scan_timestamp']

    def __str__(self):
        return f"{self.scan_id} - {self.endpoint_url} ({self.status_code})"


class VulnerableMethodScan(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    scan_id = models.CharField(max_length=255, db_index=True)
    api_url = models.URLField()
    vulnerable_method = models.CharField(max_length=20)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    description = models.TextField()
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    scan_timestamp = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vulnerable_method_scans'
        indexes = [
            models.Index(fields=['scan_id']),
            models.Index(fields=['vulnerable_method']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"Scan {self.scan_id} - {self.api_url} - {self.vulnerable_method}"


class APIVersionCheck(models.Model):
    scan_id = models.CharField(max_length=100)
    original_api_url = models.URLField()
    version = models.CharField(max_length=50)
    is_accessible = models.BooleanField()
    response_status_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)  # in seconds
    checked_at = models.DateTimeField(auto_now_add=True)
    error_message = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'api_version_checks'
        unique_together = ['scan_id', 'original_api_url', 'version']

    def __str__(self):
        return f"{self.scan_id} - {self.original_api_url} ({self.version})"