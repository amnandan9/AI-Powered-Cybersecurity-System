from django.shortcuts import render, redirect, get_object_or_404
from main_app.models import ThreatLog, ThreatCategory, URLThreat
from threat_monitoring.models import ThreatLog as MonitoringLog
from dark_web_monitoring.models import DarkWebAlert
from ai_module.models.predict import predict_threat
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from ai_module.cyber_guru import cyber_guru
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from asgiref.sync import sync_to_async
import json
from django.utils import timezone
import random
import re
from urllib.parse import urlparse
from .services import threat_analyzer

@login_required(login_url='/authentication/login/')
def dashboard(request):
    """Displays an overview of all monitoring sections."""
    try:
        # Main app threats - show only one
        main_threats = ThreatLog.objects.all().order_by('-timestamp')[:1]
        categories = ThreatCategory.objects.all().order_by('-id')[:1]
        
        # Threat monitoring data - show only one
        monitoring_threats = MonitoringLog.objects.all().order_by('-timestamp')[:1]
        
        # Dark web alerts - show only one
        dark_web_alerts = DarkWebAlert.objects.all().order_by('-timestamp')[:1]
        
        context = {
            'main_threats': main_threats,
            'categories': categories,
            'monitoring_threats': monitoring_threats,
            'dark_web_alerts': dark_web_alerts,
        }
        return render(request, 'main_app/dashboard.html', context)
    except Exception as e:
        # Log the error for debugging
        print(f"Dashboard Error: {str(e)}")
        return render(request, 'main_app/dashboard.html', {
            'main_threats': [],
            'categories': [],
            'monitoring_threats': [],
            'dark_web_alerts': [],
            'error': 'An error occurred while loading the dashboard.'
        })

@login_required(login_url='/authentication/login/')
def threats(request):
    """Render the threat analysis page."""
    try:
        # Get recent threats
        threats = ThreatLog.objects.all().order_by('-timestamp')[:10]
        return render(request, 'main_app/threats.html', {
            'threats': threats,
            'last_updated': timezone.now()
        })
    except Exception as e:
        print(f"Threats Error: {str(e)}")
        return render(request, 'main_app/threats.html', {
            'threats': [],
            'error': 'An error occurred while loading threat analysis results.'
        })

@login_required(login_url='/authentication/login/')
def analyze_logs(request):
    """Processes user-submitted IP addresses and performs real threat analysis."""
    if request.method == 'POST':
        try:
            ip = request.POST.get('ip_address')
            if not ip:
                return render(request, 'main_app/threats.html', {
                    'error': 'Please provide an IP address to analyze'
                })

            # Validate IP address format
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(ip)
                
                # Check if IP is in reserved ranges (but allow private IPs)
                if ip_obj.is_reserved and not ip_obj.is_private:
                    return render(request, 'main_app/threats.html', {
                        'error': 'Reserved IP addresses cannot be analyzed. Please provide a valid IP address.'
                    })
                
            except ValueError:
                return render(request, 'main_app/threats.html', {
                    'error': 'Invalid IP address format. Please provide a valid IPv4 address.'
                })

            # Check if IP already exists in recent threats
            recent_threat = ThreatLog.objects.filter(ip_address=ip).order_by('-timestamp').first()
            if recent_threat and (timezone.now() - recent_threat.timestamp).total_seconds() < 3600:
                return render(request, 'main_app/threats.html', {
                    'error': f'IP {ip} was analyzed recently. Please wait before analyzing again.',
                    'threats': ThreatLog.objects.all().order_by('-timestamp')[:10],
                    'last_updated': timezone.now()
                })

            # Perform real-time threat analysis
            analysis_results = threat_analyzer.analyze_ip(ip)
            
            if 'error' in analysis_results:
                return render(request, 'main_app/threats.html', {
                    'error': f'Error analyzing IP: {analysis_results["error"]}',
                    'threats': ThreatLog.objects.all().order_by('-timestamp')[:10],
                    'last_updated': timezone.now()
                })

            # Get or create the threat category
            category, _ = ThreatCategory.objects.get_or_create(
                name=analysis_results['threat_type'],
                defaults={'description': f'Detected {analysis_results["threat_type"].lower()}'}
            )
            
            # Create the threat log with analysis results
            threat = ThreatLog.objects.create(
                ip_address=ip,
                threat_type=category,
                confidence_score=analysis_results['confidence'],
                status='active',
                description=json.dumps(analysis_results['details'])
            )
            
            # Get recent threats for display
            threats = ThreatLog.objects.all().order_by('-timestamp')[:10]
            
            return render(request, 'main_app/threats.html', {
                'threats': threats,
                'analysis_results': analysis_results,
                'success': f'Analysis completed for IP: {ip}',
                'last_updated': timezone.now()
            })
        except Exception as e:
            print(f"Analysis Error: {str(e)}")
            return render(request, 'main_app/threats.html', {
                'error': f'Error analyzing IP: {str(e)}',
                'threats': ThreatLog.objects.all().order_by('-timestamp')[:10],
                'last_updated': timezone.now()
            })
    return redirect('threats')

@login_required
@csrf_exempt
async def chat_with_guru(request):
    if request.method == 'POST':
        try:
            # Print the raw request body for debugging
            print("Raw request body:", request.body)
            
            data = json.loads(request.body)
            user_message = data.get('message', '')
            
            # Print the parsed data for debugging
            print("Parsed data:", data)
            print("User message:", user_message)
            
            if not user_message:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No message provided'
                }, status=400)
            
            # Get chat history from session
            chat_history = request.session.get('chat_history', [])
            
            # Add user message to history
            chat_history.append({
                'role': 'user',
                'content': user_message,
                'timestamp': timezone.now().isoformat()
            })
            
            # Get AI response
            response = await cyber_guru.get_response(user_message)
            print("Guru response:", response)
            
            # Add AI response to history
            chat_history.append({
                'role': 'assistant',
                'content': response,
                'timestamp': timezone.now().isoformat()
            })
            
            # Update session with new history
            request.session['chat_history'] = chat_history
            
            return JsonResponse({
                'status': 'success',
                'response': response
            })
            
        except json.JSONDecodeError as e:
            print("JSON Decode Error:", str(e))
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            print("General Error:", str(e))
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    # For GET requests, render the chat interface with history
    chat_history = request.session.get('chat_history', [])
    render_sync = sync_to_async(render, thread_sensitive=True)
    return await render_sync(request, 'main_app/cyber_guru.html', {
        'chat_history': chat_history
    })

@login_required(login_url='/authentication/login/')
def threat_categories(request):
    """Display all threat categories."""
    try:
        categories = ThreatCategory.objects.all()
        return render(request, 'main_app/threat_categories.html', {
            'categories': categories
        })
    except Exception as e:
        print(f"Threat Categories Error: {str(e)}")
        return render(request, 'main_app/threat_categories.html', {
            'categories': [],
            'error': 'An error occurred while loading threat categories.'
        })

@login_required
@csrf_exempt
def fetch_latest_intelligence(request):
    """Fetches the latest threat intelligence data."""
    try:
        # Define all possible threat types with realistic descriptions
        threat_types = {
            'External Threat': 'Unauthorized access attempt from external network',
            'Internal Threat': 'Suspicious activity detected within internal network',
            'Malware Attack': 'Malicious software detected in network traffic',
            'Phishing Attempt': 'Suspicious email or website attempting to steal credentials',
            'DDoS Attack': 'Distributed Denial of Service attack detected',
            'Brute Force Attack': 'Multiple failed login attempts detected',
            'SQL Injection': 'Attempted SQL injection attack on database',
            'Cross-Site Scripting': 'XSS attack attempt detected',
            'Zero-Day Exploit': 'Exploitation of unknown vulnerability detected',
            'Port Scan': 'Suspicious port scanning activity detected',
            'Data Exfiltration': 'Unauthorized data transfer attempt detected',
            'Ransomware': 'Ransomware encryption attempt detected'
        }
        
        # Common malicious IP ranges (for demonstration purposes)
        malicious_ranges = [
            ('185.130.0.0', '185.130.255.255'),  # Known malicious range
            ('45.227.0.0', '45.227.255.255'),    # Known malicious range
            ('91.200.0.0', '91.200.255.255'),    # Known malicious range
            ('103.0.0.0', '103.0.255.255'),      # Known malicious range
            ('192.168.0.0', '192.168.255.255'),  # Internal network
            ('10.0.0.0', '10.255.255.255'),      # Internal network
            ('172.16.0.0', '172.31.255.255')     # Internal network
        ]
        
        statuses = ['active', 'investigating', 'contained', 'resolved']
        new_threats = []
        
        def generate_realistic_ip():
            # Randomly select a range
            start_ip, end_ip = random.choice(malicious_ranges)
            # Convert to integers for manipulation
            start = sum(int(x) * (256 ** (3-i)) for i, x in enumerate(start_ip.split('.')))
            end = sum(int(x) * (256 ** (3-i)) for i, x in enumerate(end_ip.split('.')))
            # Generate random IP within range
            ip_int = random.randint(start, end)
            # Convert back to IP string
            return '.'.join(str((ip_int >> (8 * i)) & 255) for i in range(3, -1, -1))
        
        # Generate one threat of each type
        for threat_name, description in threat_types.items():
            category, _ = ThreatCategory.objects.get_or_create(
                name=threat_name,
                defaults={'description': description}
            )
            
            # Generate realistic confidence score based on threat type
            base_confidence = random.uniform(70, 95)
            if threat_name in ['Zero-Day Exploit', 'Ransomware']:
                base_confidence += random.uniform(0, 5)  # Higher confidence for critical threats
            
            threat = ThreatLog.objects.create(
                ip_address=generate_realistic_ip(),
                threat_type=category,
                confidence_score=base_confidence,
                status=random.choice(statuses)
            )
            new_threats.append(threat)
        
        # If it's a GET request, redirect to the threats page
        if request.method == 'GET':
            return redirect('main_app:threats')
        
        # For POST requests, return JSON response
        return JsonResponse({
            'status': 'success',
            'new_threats': [{
                'ip_address': threat.ip_address,
                'threat_type': {
                    'name': threat.threat_type.name,
                    'description': threat.threat_type.description
                },
                'confidence_score': threat.confidence_score,
                'status': threat.status,
                'timestamp': threat.timestamp.isoformat()
            } for threat in new_threats]
        })
    except Exception as e:
        print(f"Fetch Intelligence Error: {str(e)}")
        if request.method == 'GET':
            return redirect('main_app:threats')
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@login_required(login_url='/authentication/login/')
def analyze_url(request):
    """Analyzes a URL for potential threats."""
    if request.method == 'POST':
        try:
            url = request.POST.get('url')
            if not url:
                return render(request, 'main_app/threats.html', {
                    'error': 'Please provide a URL to analyze'
                })

            # Basic URL validation
            try:
                parsed_url = urlparse(url)
                if not all([parsed_url.scheme, parsed_url.netloc]):
                    return render(request, 'main_app/threats.html', {
                        'error': 'Invalid URL format. Please provide a complete URL (e.g., https://example.com)'
                    })
            except Exception:
                return render(request, 'main_app/threats.html', {
                    'error': 'Invalid URL format. Please provide a valid URL'
                })

            # Perform real-time URL analysis
            analysis_results = threat_analyzer.analyze_url(url)
            
            if 'error' in analysis_results:
                return render(request, 'main_app/threats.html', {
                    'error': f'Error analyzing URL: {analysis_results["error"]}',
                    'url_threats': URLThreat.objects.all().order_by('-timestamp')[:10],
                    'last_updated': timezone.now()
                })

            # Get or create the threat category
            category, _ = ThreatCategory.objects.get_or_create(
                name=analysis_results['threat_type'],
                defaults={'description': f'Detected {analysis_results["threat_type"].lower()}'}
            )
            
            # Create the URL threat log
            url_threat = URLThreat.objects.create(
                url=url,
                threat_type=category,
                confidence_score=analysis_results['confidence'],
                status='active',
                description=json.dumps(analysis_results['details']),
                has_ads=analysis_results['details']['has_ads'],
                has_malware=analysis_results['details']['has_malware'],
                has_phishing=analysis_results['details']['has_phishing'],
                has_redirects=analysis_results['details']['has_redirects'],
                redirect_chain=json.dumps(analysis_results['details']['redirect_chain']),
                is_approved=analysis_results['details']['is_approved'],
                risk_level=analysis_results['details']['risk_level']
            )
            
            # Get recent URL threats for display
            url_threats = URLThreat.objects.all().order_by('-timestamp')[:10]
            
            return render(request, 'main_app/threats.html', {
                'url_threats': url_threats,
                'url_analysis_results': analysis_results,
                'success': f'URL analysis completed for: {url}',
                'last_updated': timezone.now()
            })
        except Exception as e:
            print(f"URL Analysis Error: {str(e)}")
            return render(request, 'main_app/threats.html', {
                'error': f'Error analyzing URL: {str(e)}',
                'url_threats': URLThreat.objects.all().order_by('-timestamp')[:10],
                'last_updated': timezone.now()
            })
    return redirect('threats')
