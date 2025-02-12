from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OpenAIIntegrationViewSet, AzureDeploymentViewSet, ValueMappingViewSet, ScanResultViewSet

app_name = 'scanner'

router = DefaultRouter()
router.register(r'openai', OpenAIIntegrationViewSet, basename='openai')
router.register(r'azure', AzureDeploymentViewSet, basename='azure')
router.register(r'valuemapping', ValueMappingViewSet, basename='valuemapping')
router.register(r'scanresults', ScanResultViewSet, basename='scanresults')

urlpatterns = [
    path('', include(router.urls)),
]
