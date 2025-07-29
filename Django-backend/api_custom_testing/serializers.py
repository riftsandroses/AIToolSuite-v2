from rest_framework import serializers
from .models import ScanResult

class ScanRequestSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=255)

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'