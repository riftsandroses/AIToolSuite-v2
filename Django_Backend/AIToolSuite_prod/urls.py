"""
URL configuration for AIToolSuite_prod project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/login/', include('login.urls')),
    path('api/v1/home/', include('homepage.urls')),
    path('api/v1/llm-scanner/', include('scanner.urls')),
    path('api/v1/aitm/', include('aitm.urls')),
    path('api/v1/scanner-results/', include('scanner_results.urls')),
    path('api/v1/risk-assessment/', include('risk_assessment.urls')),
    path('api/v1/connector/', include('connector.urls')),
    path('api/v1/threat-model/', include('threat_model.urls')),
    path('api/v1/api-orch/', include('api_orch.urls')),
    path('api/v1/api-custom-testing/', include('api_custom_testing.urls')),
    path('api/v1/api-2/', include('api_2.urls')),
    path('api/v1/api-4/', include('api_4.urls')),
    path('api/v1/api-6/', include('api_6.urls')),
    path('api/v1/api-7/', include('api_7.urls')),
    path('api/v1/api-8/', include('api_8.urls')),
    path('api/v1/api-9/', include('api_9.urls')),
]
