from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from .models import OpenAIIntegration, AzureDeployment, ValueMapping, ScanResult
from .serializers import OpenAIIntegrationSerializer, AzureDeploymentSerializer, ValueMappingSerializer, ScanResultSerializer
from django.conf import settings
import os
import uuid
import yaml
import subprocess
from threading import Thread
from scanner.utils.watchdog_handler import start_file_watch

class OpenAIIntegrationViewSet(viewsets.ModelViewSet):
    queryset = OpenAIIntegration.objects.all()
    serializer_class = OpenAIIntegrationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):
        integration = self.get_object()
        try:
            result_message = execute_garak_scan_openai(integration)
            return Response({"message": result_message}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class AzureDeploymentViewSet(viewsets.ModelViewSet):
    queryset = AzureDeployment.objects.all()
    serializer_class = AzureDeploymentSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):
        deployment = self.get_object()
        try:
            result_message = execute_garak_scan_azure(deployment)
            return Response({"message": result_message}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ValueMappingViewSet(viewsets.ModelViewSet):
    queryset = ValueMapping.objects.all()
    serializer_class = ValueMappingSerializer
    permission_classes = [IsAuthenticated]

class ScanResultViewSet(viewsets.ModelViewSet):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer
    permission_classes = [IsAuthenticated]

def execute_garak_scan_openai(integration):
    try:
        os.environ['OPENAI_API_KEY'] = integration.api_key
        yaml_path = os.path.join(settings.MEDIA_ROOT, 'yamls', integration.yaml_name)
        hitlog_path = yaml_path.replace('.yaml', '.hitlog.jsonl')

        command = ["garak", "--model_type", "openai", "--model_name", integration.model_name, "--config", yaml_path]

        observer_thread = Thread(target=start_file_watch, args=(hitlog_path, integration.user))
        observer_thread.daemon = True
        observer_thread.start()

        subprocess.Popen(command)
        return "Scan started successfully."
    except Exception as e:
        raise Exception(f"Error during scan execution: {e}")

def execute_garak_scan_azure(deployment):
    try:
        os.environ['AZURE_API_KEY'] = deployment.azure_api_key
        os.environ['AZURE_ENDPOINT'] = deployment.azure_endpoint_url
        os.environ['AZURE_MODEL_NAME'] = deployment.azure_model_name

        yaml_path = os.path.join(settings.MEDIA_ROOT, 'yamls', deployment.yaml_name)

        command = ["garak", "--model_type", "azure", "--model_name", deployment.azure_deployment_name, "--config", yaml_path]

        subprocess.Popen(command)
        return "Scan started successfully."
    except Exception as e:
        raise Exception(f"Error during scan execution: {e}")
