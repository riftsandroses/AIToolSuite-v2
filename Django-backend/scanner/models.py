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
