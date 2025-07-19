from django.urls import path
from . import views
from .views import chat_with_guru

app_name = "main_app"

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('threats/', views.threats, name='threats'),
    path('analyze-logs/', views.analyze_logs, name='analyze_logs'),
    path('analyze-url/', views.analyze_url, name='analyze_url'),
    path('cyber-guru/', chat_with_guru, name='cyber_guru'),
    path('threat-categories/', views.threat_categories, name='threat_categories'),
    path('fetch-intelligence/', views.fetch_latest_intelligence, name='fetch_latest_intelligence'),
]
