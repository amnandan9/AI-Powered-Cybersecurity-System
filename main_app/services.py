import requests
import json
from django.conf import settings
import time
from urllib.parse import urlparse

class ThreatAnalyzer:
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.vt_api_key,
            "Accept": "application/json"
        }

    def analyze_ip(self, ip_address):
        """Analyze IP address using VirusTotal API"""
        try:
            print(f"Starting IP analysis for: {ip_address}")
            
            # Check IP reputation
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            print(f"Requesting IP analysis from: {url}")
            response = requests.get(url, headers=self.headers)
            
            print(f"API Response Status: {response.status_code}")
            print(f"API Response: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Full API Response Data: {json.dumps(data, indent=2)}")
                
                analysis = data.get('data', {}).get('attributes', {})
                print(f"Analysis Attributes: {json.dumps(analysis, indent=2)}")
                
                # Extract relevant information
                last_analysis_stats = analysis.get('last_analysis_stats', {})
                print(f"Analysis Stats: {last_analysis_stats}")
                
                total_engines = sum(last_analysis_stats.values())
                malicious_count = last_analysis_stats.get('malicious', 0)
                
                # Calculate confidence score
                confidence_score = malicious_count / total_engines if total_engines > 0 else 0
                
                # Determine threat type
                threat_type = "Malicious" if malicious_count > 0 else "Clean"
                
                # Get additional details
                details = {
                    'last_seen': analysis.get('last_modification_date', 'Unknown'),
                    'country': analysis.get('country', 'Unknown'),
                    'as_owner': analysis.get('as_owner', 'Unknown'),
                    'reputation': analysis.get('reputation', 0),
                    'malicious_engines': malicious_count,
                    'total_engines': total_engines,
                    'analysis_results': analysis.get('last_analysis_results', {})
                }
                
                print(f"Final Analysis Details: {json.dumps(details, indent=2)}")
                
                return {
                    'ip': ip_address,
                    'threat_type': threat_type,
                    'confidence': confidence_score,
                    'details': details
                }
            else:
                print(f"API Error: {response.status_code}")
                return {
                    'error': f"API Error: {response.status_code}"
                }
        except Exception as e:
            print(f"Error in analyze_ip: {str(e)}")
            return {
                'error': str(e)
            }

    def analyze_url(self, url):
        """Analyze URL using VirusTotal API"""
        try:
            print(f"Starting URL analysis for: {url}")
            
            # Submit URL for analysis
            submit_url = f"{self.base_url}/urls"
            print(f"Submitting URL to: {submit_url}")
            response = requests.post(
                submit_url,
                headers=self.headers,
                data={"url": url}
            )
            
            print(f"Initial API Response Status: {response.status_code}")
            print(f"Initial API Response: {response.text}")
            
            if response.status_code == 200:
                analysis_id = response.json().get('data', {}).get('id')
                print(f"Analysis ID: {analysis_id}")
                
                # Wait for analysis to complete
                time.sleep(15)  # Wait for analysis to complete
                
                # Get analysis results
                results_url = f"{self.base_url}/analyses/{analysis_id}"
                print(f"Fetching results from: {results_url}")
                results_response = requests.get(results_url, headers=self.headers)
                
                print(f"Results API Response Status: {results_response.status_code}")
                print(f"Results API Response: {results_response.text}")
                
                if results_response.status_code == 200:
                    data = results_response.json()
                    print(f"Full API Response Data: {json.dumps(data, indent=2)}")
                    
                    analysis = data.get('data', {}).get('attributes', {})
                    print(f"Analysis Attributes: {json.dumps(analysis, indent=2)}")
                    
                    # Extract relevant information
                    stats = analysis.get('stats', {})
                    print(f"Analysis Stats: {stats}")
                    
                    total_engines = sum(stats.values())
                    malicious_count = stats.get('malicious', 0)
                    
                    # Calculate confidence score
                    confidence_score = malicious_count / total_engines if total_engines > 0 else 0
                    
                    # Determine threat type
                    threat_type = "Malicious" if malicious_count > 0 else "Clean"
                    
                    # Get additional details
                    details = {
                        'has_ads': analysis.get('adult', False),
                        'has_malware': malicious_count > 0,
                        'has_phishing': analysis.get('phishing', False),
                        'has_redirects': len(analysis.get('redirect_chain', [])) > 0,
                        'redirect_chain': analysis.get('redirect_chain', []),
                        'is_approved': malicious_count == 0,
                        'risk_level': 'high' if malicious_count > 0 else 'low',
                        'analysis_results': analysis.get('results', {})
                    }
                    
                    print(f"Final Analysis Details: {json.dumps(details, indent=2)}")
                    
                    return {
                        'url': url,
                        'threat_type': threat_type,
                        'confidence': confidence_score,
                        'details': details
                    }
            return {
                'error': f"API Error: {response.status_code}"
            }
        except Exception as e:
            print(f"Error in analyze_url: {str(e)}")
            return {
                'error': str(e)
            }

# Create a global instance
threat_analyzer = ThreatAnalyzer() 