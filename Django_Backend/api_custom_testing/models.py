from django.db import models

class ScanResult(models.Model):
    scan_id = models.CharField(max_length=255)
    api_id = models.CharField(max_length=255)
    vulnerability_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=50)
    details = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'api_custom_testing_scanresult'