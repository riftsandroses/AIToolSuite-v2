from rest_framework import serializers
from .models import UnboundedPaginationScan

class UnboundedPaginationScanSerializer(serializers.Serializer):
    scan_id = serializers.CharField(max_length=255)

class UnboundedPaginationResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnboundedPaginationScan
        fields = '__all__'
