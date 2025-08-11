from django.urls import path
from .views import UnboundedPaginationScanView, ScanResultsView, ScanResultsListView, VulnerableAPIsView, ScanStatsView, RateLimitScanView, ScanResultsViewTC2, ScanStatsViewTC2, ScanLogsViewTC2, ScanDetailViewTC2, StartFileUploadScanViewTC3, ScanResultsViewTC3, VulnerableApisViewTC3, ScanStatsViewTC3, FileUploadTestDetailsViewTC3, ScanSessionViewTC3, DeleteScanResultsViewTC3, ExportScanResultsViewTC3, RetestVulnerableApisViewTC3, AsyncProcessTester, TestResultsView, TestStatsView, FileDownloadScanViewTC5, ScanResultsViewTC5, ScanHistoryViewTC5, ScanStatsViewTC5, VulnerabilitiesSummaryView

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

    # TC-3 Unrestricted File Upload
    path('scan-tc3/start/', StartFileUploadScanViewTC3.as_view(), name='start_scan'),
    path('scan-tc3/results/', ScanResultsViewTC3.as_view(), name='scan_results'),
    path('scan-tc3/vulnerable/', VulnerableApisViewTC3.as_view(), name='vulnerable_apis'),
    path('scan-tc3/stats/', ScanStatsViewTC3.as_view(), name='scan_stats'),
    path('scan-tc3/session/', ScanSessionViewTC3.as_view(), name='scan_session'),
    path('results-tc3/<int:result_id>/details/', FileUploadTestDetailsViewTC3.as_view(), name='test_details'),
    path('scan-tc3/delete/', DeleteScanResultsViewTC3.as_view(), name='delete_results'),
    path('scan-tc3/export/', ExportScanResultsViewTC3.as_view(), name='export_results'),
    path('scan-tc3/retest/', RetestVulnerableApisViewTC3.as_view(), name='retest_vulnerable'),

    # TC-4 Async Task Exploits
    path('test-async-apis/', AsyncProcessTester.as_view(), name='test-async-apis'),
    path('test-results/', TestResultsView.as_view(), name='test-results'),
    path('test-stats/', TestStatsView.as_view(), name='test-stats'),

    # TC-5 Unthrottled File Downloads
    path('scan-tc5/', FileDownloadScanViewTC5.as_view(), name='file-download-scan'),
    path('results-tc5/', ScanResultsViewTC5.as_view(), name='scan-results'),
    path('results-tc5/<int:scan_id>/', ScanResultsViewTC5.as_view(), name='scan-results-detail'),
    path('history-tc5/', ScanHistoryViewTC5.as_view(), name='scan-history'),
    path('stats-tc5/', ScanStatsViewTC5.as_view(), name='scan-stats'),
    path('stats-tc5/<int:scan_id>/', ScanStatsViewTC5.as_view(), name='scan-stats-detail'),
    path('vulnerabilities-tc5/summary/', VulnerabilitiesSummaryView.as_view(), name='vulnerabilities-summary'),
]