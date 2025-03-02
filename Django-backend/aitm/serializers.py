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
        # Get the host from request or settings
        request = self.context.get('request')
        if request is not None:
            host = request.get_host().split(':')[0]  # Extract just the hostname part
        else:
            # Fallback to localhost if no request context is available
            host = 'localhost'
        
        return f"http://{host}:{obj.port}"