# api_orch/models.py
from django.db import models
from django.contrib.auth.models import User


class Scan(models.Model):
    scan_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    client_name = models.CharField(max_length=255)
    client_app_name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    postman_collection_file = models.FileField(upload_to='postman_collections/')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.scan_name} - {self.client_name}"


class PostmanAPI(models.Model):
    METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
        ('HEAD', 'HEAD'),
        ('OPTIONS', 'OPTIONS'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='postman_apis')
    name = models.CharField(max_length=255)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    url = models.URLField(max_length=2000)
    headers = models.JSONField(default=dict, blank=True)
    body = models.JSONField(default=dict, blank=True)
    authorization = models.JSONField(default=dict, blank=True)
    query_params = models.JSONField(default=dict, blank=True)
    folder_path = models.CharField(max_length=500, blank=True, null=True)
    pre_request_script = models.TextField(blank=True, null=True)
    test_script = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['folder_path', 'name']

    def __str__(self):
        return f"{self.method} {self.name} - {self.scan.scan_name}"