# api_9/urls.py
from django.urls import path
from .views import DiscoverEndpointsView, SubdomainDiscoveryAPIView, TaskStatusView, StartDocumentationScanView, GetScanResultsView, GetScanSummaryView, VulnerableMethodsScanView, ScanResultsView, APIVersionEnumerationView, APIVersionResultsView, EndpointDiscoveryView, EndpointResultsView

app_name = 'api_9'

urlpatterns = [
    path('discover-endpoints/', DiscoverEndpointsView.as_view(), name='discover_endpoints'),
    path('subdomain-endpoints/', SubdomainDiscoveryAPIView.as_view(), name='subdomain-endpoints'),
    path('task-status/<str:task_id>/', TaskStatusView.as_view(), name='task-status'),
    path('scan-documentation/', StartDocumentationScanView.as_view(), name='start-documentation-scan'),
    path('scan-results/<str:scan_id>/', GetScanResultsView.as_view(), name='get-scan-results'),
    path('scan-summary/<str:scan_id>/', GetScanSummaryView.as_view(), name='get-scan-summary'),
    path('scan/vulnerable-methods/', VulnerableMethodsScanView.as_view(), name='scan-vulnerable-methods'),
    path('scan/results/<str:scan_id>/', ScanResultsView.as_view(), name='scan-results'),
    path('version-enumeration/', APIVersionEnumerationView.as_view(), name='api-version-enumeration'),
    path('version-results/<str:scan_id>/', APIVersionResultsView.as_view(), name='api-version-results'),
    path('discover-endpoints-tc6/', EndpointDiscoveryView.as_view(), name='discover-endpoints-tc6'),
    path('endpoint-results/<str:scan_id>/', EndpointResultsView.as_view(), name='endpoint-results'),
]