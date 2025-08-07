# api_9/serializers.py
from rest_framework import serializers
from .models import UnlistedEndpoints, SubdomainDiscovery

class EndpointDiscoverySerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=100)

class UnlistedEndpointsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnlistedEndpoints
        fields = ['scan_id', 'endpoint_url', 'discovered_at', 'method', 'status_code']

class SubdomainDiscoverySerializer(serializers.ModelSerializer):
    class Meta:
        model = SubdomainDiscovery
        fields = '__all__'

class ScanRequestSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=100)
