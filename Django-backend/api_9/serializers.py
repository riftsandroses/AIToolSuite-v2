# api_9/serializers.py
from rest_framework import serializers
from .models import UnlistedEndpoints, SubdomainDiscovery, DocumentationEndpoint, VulnerableMethodScan, APIVersionCheck


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

class DocumentationScanSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=100)

class DocumentationEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentationEndpoint
        fields = '__all__'

class ScanRequestSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=255, required=True)

class VulnerableMethodScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerableMethodScan
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

class VersionCheckRequestSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=100)
    use_openai = serializers.BooleanField(default=False)

class APIVersionCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIVersionCheck
        fields = '__all__'

class VersionCheckResponseSerializer(serializers.Serializer):
    scan_id = serializers.CharField()
    total_apis_checked = serializers.IntegerField()
    total_versions_found = serializers.IntegerField()
    accessible_versions = serializers.IntegerField()
    results = APIVersionCheckSerializer(many=True)