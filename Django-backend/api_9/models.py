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
