from django.db import models
from django.contrib.auth.models import User

class OpenAIDB(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Auto-linked to logged-in user
    created_at = models.DateTimeField(auto_now_add=True)

    generator = models.CharField(max_length=10, default='openai')
    attack_name = models.CharField(max_length=255)
    scan_name = models.CharField(max_length=255)
    description = models.TextField()
    client_name = models.CharField(max_length=255)
    client_app_name = models.CharField(max_length=255)
    model_name = models.CharField(max_length=255)
    api_key = models.CharField(max_length=255)  # Store securely if necessary

    yaml_file = models.CharField(max_length=1024, null=True, blank=True)

    def __str__(self):
        return f"{self.scan_name} ({self.generator})"

class AzureDB(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Auto-linked to logged-in user
    created_at = models.DateTimeField(auto_now_add=True)

    generator = models.CharField(max_length=10, default='azure')
    attack_name = models.CharField(max_length=255)
    scan_name = models.CharField(max_length=255)
    description = models.TextField()
    client_name = models.CharField(max_length=255)
    client_app_name = models.CharField(max_length=255)
    azure_model_name = models.CharField(max_length=255)
    azure_deployment_name = models.CharField(max_length=255)
    azure_endpoint_url = models.URLField()
    azure_api_key = models.CharField(max_length=255)  # Store securely if necessary

    yaml_file = models.CharField(max_length=1024, null=True, blank=True)

    def __str__(self):
        return f"{self.scan_name} ({self.generator})"

class ScanResult(models.Model):
    # Link to the parent scan
    openai_scan = models.ForeignKey(OpenAIDB, on_delete=models.CASCADE, null=True, blank=True)
    azure_scan = models.ForeignKey(AzureDB, on_delete=models.CASCADE, null=True, blank=True)
    
    # Fields from the hitlog.jsonl
    goal = models.CharField(max_length=255, null=True, blank=True)
    prompt = models.TextField(null=True, blank=True)
    output = models.TextField(null=True, blank=True)
    trigger = models.CharField(max_length=255, null=True, blank=True)
    score = models.FloatField(null=True, blank=True)
    run_id = models.CharField(max_length=255, null=True, blank=True)
    attempt_id = models.CharField(max_length=255, null=True, blank=True)
    attempt_seq = models.IntegerField(null=True, blank=True)
    attempt_idx = models.IntegerField(null=True, blank=True)
    generator = models.CharField(max_length=255, null=True, blank=True)
    probe = models.CharField(max_length=255, null=True, blank=True)
    detector = models.CharField(max_length=255, null=True, blank=True)
    generations_per_prompt = models.IntegerField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Result {self.id} for probe {self.probe}"