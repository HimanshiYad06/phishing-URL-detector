from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json

class SafeBrowsingAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.service = build('safebrowsing', 'v4', developerKey=api_key)
        
    def check_url(self, url):
        try:
            # Create the request body
            request_body = {
                'client': {
                    'clientId': 'phishing-detector',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            # Make the API request
            response = self.service.threatMatches().find(body=request_body).execute()
            
            if 'matches' in response:
                # URL is malicious
                threats = [match['threatType'] for match in response['matches']]
                return {
                    'status': 'success',
                    'result': {
                        'is_safe': False,
                        'threats': threats,
                        'threat_level': self._get_threat_level(threats)
                    }
                }
            else:
                # URL is safe
                return {
                    'status': 'success',
                    'result': {
                        'is_safe': True,
                        'threats': [],
                        'threat_level': 'clean'
                    }
                }
                
        except HttpError as error:
            return {
                'status': 'error',
                'error': f"Google Safe Browsing API error: {str(error)}"
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': f"Error checking URL: {str(e)}"
            }
    
    def _get_threat_level(self, threats):
        if 'SOCIAL_ENGINEERING' in threats:
            return 'phishing'
        elif 'MALWARE' in threats:
            return 'malicious'
        elif 'UNWANTED_SOFTWARE' in threats or 'POTENTIALLY_HARMFUL_APPLICATION' in threats:
            return 'suspicious'
        return 'clean' 