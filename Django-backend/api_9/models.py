# api_9/models.py
from django.db import models

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