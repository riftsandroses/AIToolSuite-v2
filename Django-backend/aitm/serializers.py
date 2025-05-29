# serializers.py
from rest_framework import serializers
from .models import UserContainer

class UserContainerSerializer(serializers.ModelSerializer):
    container_url = serializers.SerializerMethodField()
    
    class Meta:
        model = UserContainer
        fields = ['id', 'container_id', 'container_name', 'port', 
                  'created_at', 'last_accessed', 'is_active', 'container_url']
        read_only_fields = ['id', 'container_id', 'container_name', 'port', 
                           'created_at', 'last_accessed', 'container_url']
    
    def get_container_url(self, obj):
        # Generate user-specific subdomain
        subdomain = f"user{obj.user.id}.dev.aitoolsuite.xyz"
        return f"https://{subdomain}"