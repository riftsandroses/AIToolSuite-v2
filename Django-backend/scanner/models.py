from django.db import models
from django.contrib.auth.models import User

class OpenAIIntegration(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_name = models.CharField(max_length=255)  # No primary_key=True here
    description = models.TextField()
    model_name = models.CharField(max_length=255)
    api_key = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    attack_name = models.TextField(blank=True, null=True)
    probe_lists = models.TextField(blank=True, null=True)
    yaml_name = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.attack_name}"


class AzureDeployment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_name = models.CharField(max_length=255)  # No primary_key=True here
    description = models.TextField()
    azure_model_name = models.CharField(max_length=255)
    azure_endpoint_url = models.URLField()
    azure_deployment_name = models.CharField(max_length=255)
    azure_api_key = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    attack_name = models.TextField(blank=True, null=True)
    probe_lists = models.TextField(blank=True, null=True)
    yaml_name = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.attack_name}"


class ValueMapping(models.Model):
    attack_name = models.CharField(max_length=255)  # Stores the name of the attack
    probes_name = models.CharField(max_length=500)  # Stores the name of the probe
    category_matrix = models.CharField(max_length=255)  # Stores the name of the category

    def __str__(self):
        return f"{self.attack_name} -> {self.probes_name}"
    
from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to the user who initiated the scan
    report_name = models.TextField(null=False, blank=False)
    goal = models.TextField(null=True, blank=True)
    prompt = models.TextField()
    output = models.TextField()
    trigger = models.TextField(null=True, blank=True)
    score = models.FloatField(null=True, blank=True)
    run_id = models.CharField(max_length=512, null=True, blank=True)
    attempt_id = models.CharField(max_length=512, null=True, blank=True)
    attempt_seq = models.IntegerField(null=True, blank=True)
    attempt_idx = models.IntegerField(null=True, blank=True)
    generator = models.CharField(max_length=512, null=True, blank=True)
    probe = models.CharField(max_length=512, null=True, blank=True)
    detector = models.CharField(max_length=512, null=True, blank=True)
    generations_per_prompt = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the record was inserted

    def __str__(self):
        return f"ScanResult {self.id} - {self.run_id}"
