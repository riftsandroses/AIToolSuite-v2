# api_9/urls.py
from django.urls import path
from .views import DiscoverEndpointsView, SubdomainDiscoveryAPIView, TaskStatusView, StartDocumentationScanView, GetScanResultsView, GetScanSummaryView

app_name = 'api_9'

urlpatterns = [
    path('discover-endpoints/', DiscoverEndpointsView.as_view(), name='discover_endpoints'),
    path('subdomain-endpoints/', SubdomainDiscoveryAPIView.as_view(), name='subdomain-endpoints'),
    path('task-status/<str:task_id>/', TaskStatusView.as_view(), name='task-status'),
    path('scan-documentation/', StartDocumentationScanView.as_view(), name='start-documentation-scan'),
    path('scan-results/<str:scan_id>/', GetScanResultsView.as_view(), name='get-scan-results'),
    path('scan-summary/<str:scan_id>/', GetScanSummaryView.as_view(), name='get-scan-summary'),
]