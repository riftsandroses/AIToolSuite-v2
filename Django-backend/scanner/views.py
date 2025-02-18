import os
import yaml
import uuid
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import OpenAIDB, AzureDB
from .serializers import OpenAIScanSerializer, AzureScanSerializer

class ScanAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Require authentication

    def generate_yaml_file(self, scan_name, client_name, client_app_name, attack_name):
        """Generates a YAML file and returns the file path and filename."""

        # Generate unique identifier
        unique_id = str(uuid.uuid4())[:8]  # Shortened UUID

        # Replace spaces with underscores in filename parts
        safe_scan_name = scan_name.replace(" ", "_")
        safe_client_name = client_name.replace(" ", "_")
        safe_client_app_name = client_app_name.replace(" ", "_")

        # Construct filename using a safe separator
        safe_filename = f"{safe_scan_name}_{safe_client_name}_{safe_client_app_name}_{unique_id}.yaml"

        # Construct full file path
        file_path = os.path.join(settings.MEDIA_ROOT, "yaml", safe_filename)

        # Construct YAML data
        yaml_data = {
            'system': {
                'verbose': 0,
                'narrow_output': False,
                'parallel_requests': False,
                'parallel_attempts': False,
                'lite': True,
                'show_z': False,
            },
            'run': {
                'seed': None,
                'deprefix': True,
                'eval_threshold': 0.5,
                'generations': 5,
                'probe_tags': None,
            },
            'plugins': {
                'model_type': None,
                'model_name': None,
                'probe_spec': attack_name,  # Mapping attack_name to probe_spec
                'detector_spec': 'auto',
                'extended_detectors': False,
                'buff_spec': None,
                'buffs_include_original_prompt': False,
                'buff_max': None,
                'detectors': {},
                'generators': {},
                'buffs': {},
                'harnesses': {},
                'probes': {
                    'encoding': {
                        'payloads': ['default']
                    }
                },
            },
            'reporting': {
                'report_prefix': safe_filename.replace(".yaml", ""),
                'taxonomy': None,
                'report_dir': os.path.join(settings.MEDIA_ROOT, "yaml"),  # Path to media/yaml
                'show_100_pass_modules': True,
            },
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Save YAML file
        with open(file_path, "w") as yaml_file:
            yaml.dump(yaml_data, yaml_file, default_flow_style=False)

        return safe_filename, file_path  # Return cleaned filename and file path

    def post(self, request, *args, **kwargs):
        generator = request.data.get('generator')

        if generator == 'openai':
            serializer = OpenAIScanSerializer(data=request.data)
            if serializer.is_valid():
                # Generate YAML file
                yaml_filename, _ = self.generate_yaml_file(
                    serializer.validated_data["scan_name"],
                    serializer.validated_data["client_name"],
                    serializer.validated_data["client_app_name"],
                    serializer.validated_data["attack_name"],
                )

                # Save in OpenAIDB
                openai_scan = OpenAIDB.objects.create(
                    user=request.user, 
                    yaml_file=yaml_filename,  # Save YAML filename only
                    **serializer.validated_data
                )

                return Response({"message": "OpenAI scan saved successfully"}, status=status.HTTP_201_CREATED)

        elif generator == 'azure':
            serializer = AzureScanSerializer(data=request.data)
            if serializer.is_valid():
                # Generate YAML file
                yaml_filename, _ = self.generate_yaml_file(
                    serializer.validated_data["scan_name"],
                    serializer.validated_data["client_name"],
                    serializer.validated_data["client_app_name"],
                    serializer.validated_data["attack_name"],
                )

                # Save in AzureDB
                azure_scan = AzureDB.objects.create(
                    user=request.user, 
                    yaml_file=yaml_filename,  # Save YAML filename only
                    **serializer.validated_data
                )

                return Response({"message": "Azure scan saved successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)