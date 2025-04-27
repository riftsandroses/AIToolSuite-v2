from rest_framework import serializers
from .models import RiskAssessment, ApplicationType

class ApplicationTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicationType
        fields = ['id', 'name']

class RiskAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskAssessment
        fields = [
            'id', 'application_name', 'business_logic', 'sensitive_data',
            'application_type', 'third_party_integrations', 'error_handling',
            'user_input_handling', 'architecture', 'hosting', 'tech_stack',
            'platforms', 'data_security', 'legacy_dependencies', 'monitoring',
            'application_description', 'risk_score', 'created_at', 'updated_at'
        ]
        read_only_fields = ['user', 'application_description', 'risk_score', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        # Set the user from the request
        validated_data['user'] = self.context['request'].user
        
        # Create the risk assessment
        risk_assessment = RiskAssessment.objects.create(**validated_data)
        
        # Generate application description and calculate risk score
        description = self.generate_application_description(risk_assessment)
        risk_assessment.application_description = description
        
        # Calculate risk score
        risk_assessment.risk_score = risk_assessment.calculate_risk_score()
        risk_assessment.save()
        
        return risk_assessment
    
    def generate_application_description(self, risk_assessment):
        """Generate application description using Ollama"""
        from .ollama_client import get_application_description
        
        # Prepare prompt for the LLM
        prompt = f"""
        Generate a comprehensive paragraph describing the following application:
        
        Application Name: {risk_assessment.application_name}
        Business Logic: {risk_assessment.business_logic}
        Sensitivity of Data: {risk_assessment.get_sensitive_data_display()}
        Application Type: {risk_assessment.application_type}
        Third-party Integrations: {risk_assessment.get_third_party_integrations_display()}
        Error Handling: {risk_assessment.get_error_handling_display()}
        User Input Handling: {risk_assessment.get_user_input_handling_display()}
        Architecture: {risk_assessment.get_architecture_display()}
        Hosting: {risk_assessment.get_hosting_display()}
        Tech Stack: {risk_assessment.tech_stack}
        Platforms: {risk_assessment.get_platforms_display()}
        Data Security: {risk_assessment.get_data_security_display()}
        Legacy Dependencies: {risk_assessment.get_legacy_dependencies_display()}
        Monitoring: {risk_assessment.get_monitoring_display()}
        
        The description should summarize the application's purpose, architecture, security considerations, and potential risk factors.
        """
        
        return get_application_description(prompt)