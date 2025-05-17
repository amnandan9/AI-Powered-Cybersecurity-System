from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import DarkWebAlert
from .services import (
    fetch_dark_web_alerts,
    analyze_alert,
    get_alerts_by_risk_level,
    get_alerts_by_threat_type,
    get_recent_alerts,
    update_alert_status
)

@login_required(login_url='/authentication/login/')
def dark_web_dashboard(request):
    """
    Displays dark web alerts with filtering and analysis options.
    """
    # Get filter parameters
    risk_level = request.GET.get('risk_level')
    threat_type = request.GET.get('threat_type')
    time_frame = request.GET.get('time_frame', '24')
    
    # Get alerts based on filters
    if risk_level:
        alerts = get_alerts_by_risk_level(risk_level)
    elif threat_type:
        alerts = get_alerts_by_threat_type(threat_type)
    else:
        alerts = get_recent_alerts(int(time_frame))
    
    context = {
        'alerts': alerts,
        'risk_levels': ['low', 'medium', 'high', 'critical'],
        'threat_types': [
            'data_breach', 'malware', 'phishing',
            'ransomware', 'exploit', 'credentials', 'other'
        ],
        'time_frames': [('1', 'Last Hour'), ('24', 'Last 24 Hours'), ('168', 'Last Week')],
        'selected_risk_level': risk_level,
        'selected_threat_type': threat_type,
        'selected_time_frame': time_frame
    }
    
    return render(request, 'dark_web_monitoring/alerts.html', context)

@login_required(login_url='/authentication/login/')
def fetch_new_alert(request):
    """
    Fetches new dark web threat intelligence.
    """
    try:
        fetch_dark_web_alerts()
        messages.success(request, 'New dark web alerts have been fetched successfully.')
    except Exception as e:
        messages.error(request, f'Error fetching alerts: {str(e)}')
    
    return redirect('darkweb:dark_web_dashboard')

@login_required(login_url='/authentication/login/')
def analyze_alert_view(request, alert_id):
    """
    Analyzes a specific alert and updates its status.
    """
    try:
        if analyze_alert(alert_id):
            messages.success(request, 'Alert analysis completed successfully.')
        else:
            messages.error(request, 'Alert not found.')
    except Exception as e:
        messages.error(request, f'Error analyzing alert: {str(e)}')
    
    return redirect('darkweb:dark_web_dashboard')

@login_required(login_url='/authentication/login/')
def update_alert_status_view(request, alert_id):
    """
    Updates the status of a specific alert.
    """
    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in ['new', 'investigating', 'resolved', 'false_positive']:
            if update_alert_status(alert_id, new_status):
                messages.success(request, 'Alert status updated successfully.')
            else:
                messages.error(request, 'Alert not found.')
        else:
            messages.error(request, 'Invalid status provided.')
    
    return redirect('darkweb:dark_web_dashboard')
