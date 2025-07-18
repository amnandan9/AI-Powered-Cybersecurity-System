from django.contrib import admin
from .models import ThreatLog, ThreatCategory

admin.site.register(ThreatLog)
admin.site.register(ThreatCategory)
