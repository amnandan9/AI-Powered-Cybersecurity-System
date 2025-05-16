from django.urls import path
from . import views

app_name = 'darkweb'

urlpatterns = [
    path('darkweb/', views.dark_web_dashboard, name='dark_web_dashboard'),
    path('fetch-alert/', views.fetch_new_alert, name='fetch_new_alert'),
    path('analyze-alert/<int:alert_id>/', views.analyze_alert_view, name='analyze_alert'),
    path('update-status/<int:alert_id>/', views.update_alert_status_view, name='update_alert_status'),
]
