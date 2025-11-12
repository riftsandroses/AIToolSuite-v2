from .models import SSRFCandidate, LLMAnalysisResult, SSRFProof
from rest_framework import serializers
from api_orch.serializers import PostmanAPISerializer

class SSRFCandidateSerializer(serializers.ModelSerializer):
    api_info = PostmanAPISerializer(source='api', read_only=True)  # Nested serializer for API details

    class Meta:
        model = SSRFCandidate
        fields = [
            'id', 'api', 'api_info', 'risk_score', 'risk_factors',
            'vulnerable_components', 'identified_at'
        ]
        read_only_fields = ['id', 'api', 'api_info', 'identified_at']


class LLMAnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = LLMAnalysisResult
        # Add all the new fields from your model
        fields = [
            'id', 'ssrf_candidate', 'provider', 'model_used', 'prompt_sent',
            'raw_llm_response', 'analysis_timestamp',
            
            # --- New fields that your React component needs ---
            'is_ssrf_candidate', 
            'primary_payload_category', 
            'vector_category',
            'recommended_payload',
            'analysis_run_id',
            'batch_number',
            
            # --- Deprecated fields (you can keep or remove) ---
            'parsed_analysis', 
            'overall_risk', 
            'critical_findings_count'
        ]
        read_only_fields = ['id', 'ssrf_candidate', 'analysis_timestamp']

class SSRFProofSerializer(serializers.ModelSerializer):
    class Meta:
        model = SSRFProof
        fields = [
            'id', 'ssrf_candidate', 'payload_used', 'injection_point',
            'target_internal_ip_or_domain', 'proof_details', 'exploitation_timestamp',
            'status'
        ]
        read_only_fields = ['id', 'ssrf_candidate', 'exploitation_timestamp']