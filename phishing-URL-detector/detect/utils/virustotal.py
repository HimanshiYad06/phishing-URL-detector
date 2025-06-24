import requests
import time
import hashlib
import json
import base64

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def scan_url(self, url):
        try:
            # First, encode the URL in base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            # Check if the URL has already been analyzed
            url_report_url = f"{self.base_url}/urls/{url_id}"
            response = requests.get(url_report_url, headers=self.headers)
            
            if response.status_code == 404:
                # URL hasn't been analyzed yet, submit it
                scan_url = f"{self.base_url}/urls"
                data = {
                    "url": url
                }
                
                response = requests.post(scan_url, json=data, headers=self.headers)
                response.raise_for_status()
                
                # Wait for analysis to complete
                time.sleep(5)
                
                # Get the report
                response = requests.get(url_report_url, headers=self.headers)
                response.raise_for_status()
            
            result = response.json()
            
            # Process the results
            stats = result['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())
            
            # Determine the status
            if positives == 0:
                status = "clean"
            elif positives <= 3:
                status = "suspicious"
            else:
                status = "malicious"
                
            # Check for phishing specifically
            categories = result['data']['attributes'].get('categories', [])
            is_phishing = "phishing" in categories or "phishing" in str(categories).lower()
            
            return {
                "status": "success",
                "result": {
                    "positives": positives,
                    "total": total,
                    "status": status,
                    "is_phishing": is_phishing,
                    "categories": categories,
                    "scan_date": result['data']['attributes'].get('last_analysis_date'),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
                }
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": str(e)
            } 