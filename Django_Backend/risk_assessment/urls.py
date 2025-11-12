from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'application-types', views.ApplicationTypeViewSet)
router.register(r'assessments', views.RiskAssessmentViewSet, basename='risk-assessment')

urlpatterns = [
    path('', include(router.urls)),
]