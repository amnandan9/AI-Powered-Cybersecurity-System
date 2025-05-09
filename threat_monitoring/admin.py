from django.contrib import admin
from .models import ThreatLog

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ('threat_type', 'source_ip', 'destination_ip', 'severity', 'timestamp')
    search_fields = ('threat_type', 'source_ip', 'destination_ip')
    list_filter = ('severity', 'timestamp')
