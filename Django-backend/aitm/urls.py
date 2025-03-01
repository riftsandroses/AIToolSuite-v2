# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserContainerViewSet

router = DefaultRouter()
router.register(r'containers', UserContainerViewSet, basename='container')

urlpatterns = [
    path('', include(router.urls)),
]