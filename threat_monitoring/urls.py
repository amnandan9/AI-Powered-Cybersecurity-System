from django.urls import path
from . import views

app_name = 'monitoring'

urlpatterns = [
    path('dashboard/', views.dashboard, name='threat_dashboard'),
    path('logs/', views.logs_view, name='threat_logs'),
    path('fetch-intelligence/', views.fetch_latest_intelligence, name='fetch_intelligence'),
    path('analyze-threat/<int:threat_id>/', views.analyze_threat_view, name='analyze_threat'),
    path('update-status/<int:threat_id>/', views.update_threat_status_view, name='update_threat_status'),
    path('traffic-analysis/', views.traffic_analysis, name='traffic_analysis'),
    path('traffic-analysis/<int:analysis_id>/', views.traffic_analysis_detail, name='traffic_analysis_detail'),
    path('threat-map/', views.threat_map_view, name='threat_map'),
]
