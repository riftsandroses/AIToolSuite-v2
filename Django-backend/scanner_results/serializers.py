from rest_framework import serializers
from .models import ProbeControlMapping, ScanResultView

class ProbeControlMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProbeControlMapping
        fields = ['probe_name', 'control_title', 'control_description', 
                  'control_observation', 'control_impact', 'control_recommendation']

class ScanResultViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResultView
        fields = ['scan_id', 'probe_name', 'prompt', 'output', 'control_title', 
                  'control_description', 'control_observation', 'control_impact', 
                  'control_recommendation', 'severity', 'owasp_top_10_for_llms', 'mitre_atlas']