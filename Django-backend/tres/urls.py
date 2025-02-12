from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TresViewSet, LLMToolViewSet

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'tres', TresViewSet, basename='tres')
router.register(r'llmtool', LLMToolViewSet, basename='llmtool')

# Include router URLs
urlpatterns = [
    path('', include(router.urls)),
]

