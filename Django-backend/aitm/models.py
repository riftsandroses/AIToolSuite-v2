# models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class UserContainer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='container')
    container_id = models.CharField(max_length=100)
    container_name = models.CharField(max_length=150)
    port = models.CharField(max_length=10, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.user.username}'s Container"
    
    class Meta:
        verbose_name = "User Container"
        verbose_name_plural = "User Containers"