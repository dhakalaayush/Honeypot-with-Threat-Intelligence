import requests
import json

API_KEY = '2bd42e82e3590d487833d970d8f0577303458133f3a1b197364604976f136eb49f5f6114bcb3ef3b'

def check_ip_reputation(ip_address):
    # AbuseIPDB APIv2 check endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # Check every reports from the last 90 days
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status() # Check for HTTP errors
        
        # Parse the JSON response
        data = response.json()['data']
        
        # Extract the specific metrics
        report = {
            'ip': data.get('ipAddress'),
            'score': data.get('abuseConfidenceScore'),
            'country': data.get('countryCode'),
            'isp': data.get('isp'),
            'total_reports': data.get('totalReports')
        }
        
        print(f"[*] Threat Intel for {report['ip']}: Score {report['score']}/100 | {report['country']} | {report['isp']}")
        return report
        
    except requests.exceptions.RequestException as e:
        print(f"[!] API Request failed: {e}")
        return None

# Quick test for a known malicious IP (or a random one like 8.8.8.8)
if __name__ == "__main__":
    test_ip = "118.25.6.39" 
    check_ip_reputation(test_ip)