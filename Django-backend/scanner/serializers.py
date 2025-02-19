from rest_framework import serializers
from .models import OpenAIDB, AzureDB

class OpenAIScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenAIDB
        exclude = ['user', 'created_at']  # Exclude user since we assign it in the view

class AzureScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = AzureDB
        exclude = ['user', 'created_at']  # Exclude user since we assign it in the view
