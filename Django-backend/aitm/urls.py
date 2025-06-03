# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserContainerViewSet

router = DefaultRouter()
router.register(r'containers', UserContainerViewSet, basename='container')

urlpatterns = [
    path('', include(router.urls)),
    # FIXED: The get-or-create endpoint will be available at:
    # /api/v1/aitm/containers/get-or-create/
    # This matches what the React component expects
]