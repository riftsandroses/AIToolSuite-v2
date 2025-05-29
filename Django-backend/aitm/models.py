# models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserContainer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    container_id = models.CharField(max_length=255)
    container_name = models.CharField(max_length=255)
    port = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'user_containers'
        
    def __str__(self):
        return f"{self.user.username} - {self.container_name}"
    
    @property
    def subdomain(self):
        """Generate user-specific subdomain"""
        return f"user{self.user.id}.dev.aitoolsuite.xyz"