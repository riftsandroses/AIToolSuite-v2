from rest_framework import serializers
from .models import OpenAIIntegration, AzureDeployment, ValueMapping, ScanResult

class ValueMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ValueMapping
        fields = '__all__'

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'


class OpenAIIntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenAIIntegration
        fields = ['scan_name', 'description', 'model_name', 'api_key']

class AzureDeploymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = AzureDeployment
        fields = ['scan_name', 'description', 'azure_model_name', 'azure_endpoint_url', 'azure_deployment_name', 'azure_api_key']
