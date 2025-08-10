from django.urls import path
from . import views

urlpatterns = [
    path('scan-unbounded-pagination/', views.UnboundedPaginationScanView.as_view(), name='scan_unbounded_pagination'),
    path('scan-results-tc1/<str:scan_id>/', views.ScanResultsView.as_view(), name='get_scan_results'),
    path('scan-results-tc1/', views.ScanResultsListView.as_view(), name='list_scan_results'),
    path('vulnerable-apis-tc1/', views.VulnerableAPIsView.as_view(), name='vulnerable_apis'),
    path('scan-stats-tc1/', views.ScanStatsView.as_view(), name='scan_statistics'),
]