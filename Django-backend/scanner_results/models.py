from django.db import models

class ProbeControlMapping(models.Model):
    """
    Static mapping table for probe information and security controls
    """
    probe_name = models.CharField(max_length=255, unique=True)
    control_title = models.CharField(max_length=255)
    control_description = models.TextField()
    control_observation = models.TextField()
    control_impact = models.TextField()
    control_recommendation = models.TextField()

    def __str__(self):
        return self.probe_name

class ScanResultView(models.Model):
    """
    View model to combine scanner_scanresult data with ProbeControlMapping
    This is not a real DB table but serves as a model for the API
    """
    scan_id = models.CharField(max_length=255)
    probe_name = models.CharField(max_length=255)
    prompt = models.TextField()
    output = models.TextField()
    control_title = models.CharField(max_length=255, null=True, blank=True)
    control_description = models.TextField(null=True, blank=True)
    control_observation = models.TextField(null=True, blank=True)
    control_impact = models.TextField(null=True, blank=True)
    control_recommendation = models.TextField(null=True, blank=True)

    class Meta:
        managed = False  # Django won't create a table for this model