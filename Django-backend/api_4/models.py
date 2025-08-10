from django.db import models
from django.utils import timezone

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