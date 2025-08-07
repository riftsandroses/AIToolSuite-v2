# api_9/urls.py
from django.urls import path
from .views import DiscoverEndpointsView, SubdomainDiscoveryAPIView, TaskStatusView

app_name = 'api_9'

urlpatterns = [
    path('discover-endpoints/', DiscoverEndpointsView.as_view(), name='discover_endpoints'),
    path('subdomain-endpoints/', SubdomainDiscoveryAPIView.as_view(), name='subdomain-endpoints'),
    path('task-status/<str:task_id>/', TaskStatusView.as_view(), name='task-status'),
]