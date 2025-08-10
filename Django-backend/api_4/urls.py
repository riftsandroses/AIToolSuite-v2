from django.urls import path
from .views import UnboundedPaginationScanView, ScanResultsView, ScanResultsListView, VulnerableAPIsView, ScanStatsView, RateLimitScanView, ScanResultsViewTC2, ScanStatsViewTC2, ScanLogsViewTC2, ScanDetailViewTC2

urlpatterns = [
    # TC-1 Unbounded Pagination
    path('scan-unbounded-pagination/', UnboundedPaginationScanView.as_view(), name='scan_unbounded_pagination'),
    path('scan-results-tc1/<str:scan_id>/', ScanResultsView.as_view(), name='get_scan_results'),
    path('scan-results-tc1/', ScanResultsListView.as_view(), name='list_scan_results'),
    path('vulnerable-apis-tc1/', VulnerableAPIsView.as_view(), name='vulnerable_apis'),
    path('scan-stats-tc1/', ScanStatsView.as_view(), name='scan_statistics'),

    # TC-2 Rate Limiting
    path('scan-rate-limiting/', RateLimitScanView.as_view(), name='rate-limit-scan'),
    path('scan-results-tc2/', ScanResultsViewTC2.as_view(), name='scan-results-tc2'),
    path('scan-results-tc2/<int:scan_record_id>/', ScanDetailViewTC2.as_view(), name='scan-detail-tc2'),
    path('scan-stats-tc2/', ScanStatsViewTC2.as_view(), name='scan-stats-tc2'),
    path('scan-logs-tc2/', ScanLogsViewTC2.as_view(), name='scan-logs-tc2'),
]