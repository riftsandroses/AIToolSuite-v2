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
    
    # New field for test case selections
    test_case_selections = models.JSONField(default=dict, blank=True, help_text="Selected test cases for this scan")
    
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


class TestCaseSelection(models.Model):
    """Model to store available test cases and their categories"""
    
    API_CATEGORIES = [
        ('API1', 'API1:2023'),
        ('API2', 'API2:2023'),
        ('API3', 'API3:2023'),
        ('API4', 'API4:2023'),
        ('API5', 'API5:2023'),
        ('API6', 'API6:2023'),
        ('API7', 'API7:2023'),
        ('API8', 'API8:2023'),
        ('API9', 'API9:2023'),
    ]
    
    TEST_CASE_CHOICES = [
        ('TC-1', 'TC-1: Unlisted Endpoints'),
        ('TC-2', 'TC-2: Access Staging/Dev Environments'),
        ('TC-3', 'TC-3: API Documentation Exposure'),
        ('TC-4', 'TC-4: Verb Tunneling'),
        ('TC-5', 'TC-5: Version Enumeration of APIs'),
        ('TC-6', 'TC-6: Monitoring/Health Endpoints'),
        ('TC-7', 'TC-7: Admin APIs'),
    ]
    
    api_category = models.CharField(max_length=10, choices=API_CATEGORIES)
    test_case = models.CharField(max_length=10, choices=TEST_CASE_CHOICES)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['api_category', 'test_case']
        ordering = ['api_category', 'test_case']
    
    def __str__(self):
        return f"{self.api_category} - {self.test_case}"