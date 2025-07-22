# api_orch/urls.py
from django.urls import path
from .views import (
    ScanCreateView,
    ScanListView,
    ScanDetailView,
    ScanUpdateView,
    ScanDeleteView,
    PostmanAPIListView,
    PostmanAPIDetailView,
    PostmanAPIUpdateView,
    PostmanAPIDeleteView,
    PostmanAPICreateView,
    ScanTestCaseSelectionView,
    AvailableTestCasesView,
    BulkTestCaseSelectionView,
)

app_name = 'api_orch'

urlpatterns = [
    # Scan URLs
    path('scans/', ScanListView.as_view(), name='scan-list'),
    path('scans/create/', ScanCreateView.as_view(), name='scan-create'),
    path('scans/<int:pk>/', ScanDetailView.as_view(), name='scan-detail'),
    path('scans/<int:pk>/update/', ScanUpdateView.as_view(), name='scan-update'),
    path('scans/<int:pk>/delete/', ScanDeleteView.as_view(), name='scan-delete'),
    
     # Test Case Selection URLs
    path('scans/<int:scan_id>/test-cases/', ScanTestCaseSelectionView.as_view(), name='scan-test-cases'),
    path('scans/bulk-test-cases/', BulkTestCaseSelectionView.as_view(), name='bulk-test-cases'),
    path('test-cases/available/', AvailableTestCasesView.as_view(), name='available-test-cases'),

    # PostmanAPI URLs
    path('scans/<int:scan_id>/apis/', PostmanAPIListView.as_view(), name='postman-api-list'),
    path('scans/<int:scan_id>/apis/create/', PostmanAPICreateView.as_view(), name='postman-api-create'),
    path('scans/<int:scan_id>/apis/<int:pk>/', PostmanAPIDetailView.as_view(), name='postman-api-detail'),
    path('scans/<int:scan_id>/apis/<int:pk>/update/', PostmanAPIUpdateView.as_view(), name='postman-api-update'),
    path('scans/<int:scan_id>/apis/<int:pk>/delete/', PostmanAPIDeleteView.as_view(), name='postman-api-delete'),
]