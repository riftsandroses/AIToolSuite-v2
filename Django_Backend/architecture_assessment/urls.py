from django.urls import path
from .views import (
    AssessmentListCreateView,
    AssessmentDetailView,
    AssessmentReportView,
    VulnerabilityListView,
    VulnerabilityDetailView,
    RemediationControlListCreateView,
    RemediationControlDetailView,
    AssessmentHistoryView,
    AssessmentStatisticsView
)

app_name = 'architecture_assessment'

urlpatterns = [
    # Assessment endpoints
    path('assessments/', AssessmentListCreateView.as_view(), name='assessment-list-create'),
    path('assessments/<uuid:pk>/', AssessmentDetailView.as_view(), name='assessment-detail'),
    path('assessments/<uuid:pk>/report/', AssessmentReportView.as_view(), name='assessment-report'),
    path('assessments/<uuid:pk>/history/', AssessmentHistoryView.as_view(), name='assessment-history'),
    
    # Vulnerability endpoints
    path('assessments/<uuid:pk>/vulnerabilities/', VulnerabilityListView.as_view(), name='vulnerability-list'),
    path('vulnerabilities/<uuid:pk>/', VulnerabilityDetailView.as_view(), name='vulnerability-detail'),
    
    # Remediation control endpoints
    path('vulnerabilities/<uuid:pk>/controls/', RemediationControlListCreateView.as_view(), name='remediation-control-list-create'),
    path('controls/<uuid:pk>/', RemediationControlDetailView.as_view(), name='remediation-control-detail'),
    
    # Statistics
    path('statistics/', AssessmentStatisticsView.as_view(), name='statistics'),
]