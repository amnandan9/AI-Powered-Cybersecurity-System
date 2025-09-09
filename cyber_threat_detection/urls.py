from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('main_app.urls', namespace='main_app')),
    path('monitoring/', include('threat_monitoring.urls', namespace='monitoring')),
    path('darkweb/', include('dark_web_monitoring.urls', namespace='darkweb')),
    path('authentication/', include('authentication.urls', namespace='authentication')),
    path('feedback/', include('feedback.urls', namespace='feedback')),
]

# maintenance 2025-09-09
