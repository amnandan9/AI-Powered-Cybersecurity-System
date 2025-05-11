from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import ThreatLog, WebsiteTrafficAnalysis
from .services import (
    get_recent_threats,
    get_threat_stats,
    analyze_threat,
    update_threat_status,
    start_threat_monitoring,
    monitor_network_traffic,
    analyze_website_traffic,
    get_traffic_analysis,
    get_recent_analyses,
    get_location_info
)
from datetime import datetime, timedelta
from random import choice, randint
from django.views.decorators.csrf import csrf_exempt
import logging
import random

# Start threat monitoring when the module is imported
monitor_thread = start_threat_monitoring()

logger = logging.getLogger(__name__)

@login_required(login_url='/authentication/login/')
def dashboard(request):
    """
    Displays the threat monitoring dashboard with real-time threat data.
    """
    # Get filter parameters
    time_frame = request.GET.get('time_frame', '24')
    severity = request.GET.get('severity')
    
    # Get recent threats
    threats = get_recent_threats(hours=int(time_frame))
    if severity:
        threats = threats.filter(severity=severity)
    
    # Limit to only 5 threats
    threats = threats[:5]
    
    # Get threat statistics
    stats = get_threat_stats()
    
    context = {
        'threats': threats,
        'stats': stats,
        'severities': ['low', 'medium', 'high', 'critical'],
        'time_frames': [
            ('1', 'Last Hour'),
            ('24', 'Last 24 Hours'),
            ('168', 'Last Week')
        ],
        'selected_severity': severity,
        'selected_time_frame': time_frame,
        'last_updated': datetime.now()
    }
    return render(request, 'threat_monitoring/dashboard.html', context)

@login_required(login_url='/authentication/login/')
def fetch_latest_intelligence(request):
    """
    Fetches the latest threat intelligence and updates the dashboard.
    """
    try:
        # Generate new threats
        threat_types = ['port_scan', 'ddos', 'malware', 'unauthorized_access', 'data_exfiltration']
        severities = ['low', 'medium', 'high', 'critical']
        
        # Generate 5-8 new threats
        num_threats = random.randint(5, 8)
        new_threats_created = 0
        
        for _ in range(num_threats):
            try:
                # Generate valid public IP addresses
                # First octet: 1-126, 128-223 (excluding private ranges)
                first_octet = random.choice([
                    random.randint(1, 126),  # Class A
                    random.randint(128, 191),  # Class B
                    random.randint(192, 223)   # Class C
                ])
                
                # Generate the rest of the IP address
                source_ip = f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
                destination_ip = f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
                
                # Get real location data
                source_location = get_location_info(source_ip)
                destination_location = get_location_info(destination_ip)
                
                # Generate random threat details with more variety
                threat_type = random.choice(threat_types)
                severity = random.choice(severities)
                risk_score = random.randint(30, 95)
                confidence_score = random.randint(60, 95)
                protocol = random.choice(['TCP', 'UDP', 'ICMP'])
                port = random.randint(1, 65535)
                packet_count = random.randint(1, 1000)
                duration = timedelta(seconds=random.randint(1, 300))
                
                # Create the threat
                ThreatLog.objects.create(
                    source_ip=source_ip,
                    source_location=source_location,
                    destination_ip=destination_ip,
                    destination_location=destination_location,
                    threat_type=threat_type,
                    severity=severity,
                    description=f"New threat detected: {random.choice(['Port scanning', 'Suspicious traffic', 'Malware activity', 'Unauthorized access attempt', 'Data exfiltration attempt', 'DDoS attack pattern'])}",
                    ai_risk_score=risk_score,
                    confidence_score=confidence_score,
                    protocol=protocol,
                    port=port,
                    packet_count=packet_count,
                    duration=duration,
                    status='new'
                )
                new_threats_created += 1
            except Exception as e:
                logger.error(f"Error creating new threat: {str(e)}")
                continue
        
        # Get updated stats
        stats = get_threat_stats()
        
        # Return JSON response
        return JsonResponse({
            'success': True,
            'message': f'Successfully added {new_threats_created} new threats.',
            'stats': {
                'total': stats['total'],
                'active': stats['active'],
                'critical': stats['critical'],
                'resolved': stats['resolved']
            }
        })
    except Exception as e:
        logger.error(f"Error in fetch_latest_intelligence: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error updating threats: {str(e)}'
        }, status=500)

@login_required(login_url='/authentication/login/')
def logs_view(request):
    """
    Displays all threat logs with filtering options.
    """
    # Get filter parameters
    severity = request.GET.get('severity')
    threat_type = request.GET.get('threat_type')
    time_frame = request.GET.get('time_frame', '24')
    status = request.GET.get('status')
    
    # Get threats based on filters
    threats = get_recent_threats(hours=int(time_frame))
    
    if severity:
        threats = threats.filter(severity=severity)
    if threat_type:
        threats = threats.filter(threat_type=threat_type)
    if status:
        threats = threats.filter(status=status)
    
    # Limit to only 5 threats
    threats = threats[:5]
    
    context = {
        'threats': threats,
        'severities': ['low', 'medium', 'high', 'critical'],
        'threat_types': [
            'port_scan', 'ddos', 'malware', 'unauthorized_access',
            'data_exfiltration'
        ],
        'statuses': ['new', 'investigating', 'contained', 'resolved', 'false_positive'],
        'time_frames': [
            ('1', 'Last Hour'),
            ('24', 'Last 24 Hours'),
            ('168', 'Last Week')
        ],
        'selected_severity': severity,
        'selected_type': threat_type,
        'selected_status': status,
        'selected_time_frame': time_frame
    }
    return render(request, 'threat_monitoring/logs.html', context)

@login_required(login_url='/authentication/login/')
def analyze_threat_view(request, threat_id):
    """
    Analyzes a specific threat and updates its status.
    """
    try:
        if analyze_threat(threat_id):
            messages.success(request, 'Threat analysis completed successfully.')
        else:
            messages.error(request, 'Threat not found.')
    except Exception as e:
        messages.error(request, f'Error analyzing threat: {str(e)}')
    
    return redirect('monitoring:threat_logs')

@login_required(login_url='/authentication/login/')
def update_threat_status_view(request, threat_id):
    """
    Updates the status of a specific threat.
    """
    try:
        if request.method == 'POST':
            new_status = request.POST.get('status')
            logger.info(f"Updating threat {threat_id} to status {new_status}")
            
            if new_status in ['new', 'investigating', 'contained', 'resolved', 'false_positive']:
                if update_threat_status(threat_id, new_status):
                    logger.info(f"Successfully updated threat {threat_id} to {new_status}")
                    messages.success(request, 'Threat status updated successfully.')
                else:
                    logger.error(f"Failed to update threat {threat_id} - threat not found")
                    messages.error(request, 'Threat not found.')
            else:
                logger.error(f"Invalid status provided: {new_status}")
                messages.error(request, 'Invalid status provided.')
        else:
            logger.error("Invalid request method for status update")
            messages.error(request, 'Invalid request method.')
    except Exception as e:
        logger.error(f"Error updating threat status: {str(e)}")
        messages.error(request, f'Error updating threat status: {str(e)}')
    
    return redirect('monitoring:threat_dashboard')

@login_required(login_url='/authentication/login/')
def traffic_analysis(request):
    """
    Displays the website traffic analysis page.
    """
    if request.method == 'POST':
        url = request.POST.get('website_url')
        if url:
            analysis = analyze_website_traffic(url)
            if analysis:
                messages.success(request, 'Traffic analysis completed successfully.')
                return redirect('monitoring:traffic_analysis_detail', analysis_id=analysis.id)
            else:
                messages.error(request, 'Error analyzing website traffic.')
    
    recent_analyses = get_recent_analyses()
    context = {
        'recent_analyses': recent_analyses
    }
    return render(request, 'threat_monitoring/traffic_analysis.html', context)

@login_required(login_url='/authentication/login/')
def traffic_analysis_detail(request, analysis_id):
    """
    Displays detailed results of a traffic analysis.
    """
    analysis = get_traffic_analysis(analysis_id)
    if not analysis:
        messages.error(request, 'Analysis not found.')
        return redirect('monitoring:traffic_analysis')
    
    # Calculate percentages for traffic sources
    traffic_sources = {}
    total_requests = analysis.results['analysis_summary']['total_requests']
    for source, count in analysis.results['traffic_sources'].items():
        percentage = (count / total_requests) * 100 if total_requests > 0 else 0
        traffic_sources[source] = {
            'count': count,
            'percentage': round(percentage, 1)
        }
    
    context = {
        'analysis': analysis,
        'results': analysis.results,
        'traffic_sources': traffic_sources
    }
    return render(request, 'threat_monitoring/traffic_analysis_detail.html', context)

def threat_map_view(request):
    """
    View for displaying the global threat intelligence map
    """
    return render(request, 'threat_map.html')
