from django.urls import path
from .views import TresView, LLMToolView

urlpatterns = [
    path('', TresView.as_view(), name='tres'),  
    path('llmtool/', LLMToolView.as_view(), name='llmtool'),
]
