from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProbeControlMappingViewSet, ScanResultsViewSet

router = DefaultRouter()
router.register(r'mappings', ProbeControlMappingViewSet)
router.register(r'results', ScanResultsViewSet, basename='results')

urlpatterns = [
    path('', include(router.urls)),
]