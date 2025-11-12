# threat_model/serializers.py

from rest_framework import serializers
from .models import ThreatModel,History

class ThreatModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatModel
        # These are the fields that will be shown to the user in the list
        fields = ['id', 'assessment_name', 'app_name', 'client_name', 'status', 'created_at']

class ThreatModelDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatModel
        # Exposes all fields for a detailed view/edit form.
        fields = [
            'id', 'assessment_name', 'app_name', 'client_name',
            'description', 'authentication_methods', 'is_internet_facing',
            'handles_sensitive_data', 'data_classification',
            'deployment_environment', 'compliance_requirements',
            'user_types', 'third_party_integrations', 'critical_assets',
            'technology_stack', 'status', 'created_at', 'updated_at'
        ]
        # app_name is used for directory paths and should not be changed after creation.
        read_only_fields = ['id', 'app_name', 'status', 'created_at', 'updated_at']
        
class HistorySerializer(serializers.ModelSerializer):
    # Use StringRelatedField to show the human-readable name of the threat model
    threat_model = serializers.StringRelatedField()
    # Use a CharField with a source to get the display name of the choice field
    action = serializers.CharField(source='get_action_display')

    class Meta:
        model = History
        fields = ['id', 'threat_model', 'action', 'details', 'timestamp']