from rest_framework import viewsets, permissions
from .permissions import IsOwner
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import RiskAssessment, ApplicationType
from .serializers import RiskAssessmentSerializer, ApplicationTypeSerializer

class ApplicationTypeViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing application types"""
    queryset = ApplicationType.objects.all()
    serializer_class = ApplicationTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

class RiskAssessmentViewSet(viewsets.ModelViewSet):
    """ViewSet for managing risk assessments"""
    serializer_class = RiskAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwner]
    
    def get_queryset(self):
        """Return only risk assessments created by the current user"""
        return RiskAssessment.objects.filter(user=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        """Save the risk assessment with the current user"""
        serializer.save(user=self.request.user)
    
    @action(detail=True, methods=['get'])
    def refresh_description(self, request, pk=None):
        """Refresh the application description using the Ollama LLM"""
        risk_assessment = self.get_object()
        
        # Regenerate description
        from .ollama_client import get_application_description
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
        
        risk_assessment.application_description = get_application_description(prompt)
        risk_assessment.save()
        
        return Response({
            'application_description': risk_assessment.application_description
        })
    
    @action(detail=True, methods=['get'])
    def recalculate_risk(self, request, pk=None):
        """Recalculate the risk score"""
        risk_assessment = self.get_object()
        risk_assessment.risk_score = risk_assessment.calculate_risk_score()
        risk_assessment.save()
        
        return Response({
            'risk_score': risk_assessment.risk_score
        })