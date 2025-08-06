# api_9/urls.py
from django.urls import path
from .views import DiscoverEndpointsView

app_name = 'api_9'

urlpatterns = [
    path('discover-endpoints/', DiscoverEndpointsView.as_view(), name='discover_endpoints'),
]