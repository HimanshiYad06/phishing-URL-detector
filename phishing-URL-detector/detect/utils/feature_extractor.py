import re
import urllib.parse
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import numpy as np
from collections import Counter

class URLFeatureExtractor:
    def __init__(self):
        # Initialize lists of suspicious TLDs and words
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date',
            '.bid', '.download', '.loan', '.racing', '.win', '.link', '.click',
            '.party', '.gdn', '.stream', '.review', '.trade', '.accountant',
            '.science', '.faith', '.webcam', '.pw', '.tech', '.cc', '.rest',
            '.su', '.ru', '.info', '.online', '.site', '.website', '.space'
        ]
        
        self.suspicious_words = [
            'login', 'signin', 'verify', 'secure', 'account', 'banking',
            'password', 'credential', 'confirm', 'update', 'paypal', 'amazon',
            'apple', 'microsoft', 'google', 'facebook', 'instagram', 'security',
            'authenticate', 'wallet', 'verification', 'suspended', 'unusual',
            'activity', 'limited', 'access', 'validate', 'unauthorized',
            'watch', 'movie', 'stream', 'download', 'free', 'premium'
        ]

        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'instagram.com', 'github.com', 'spotify.com',
            'wikipedia.org', 'reddit.com', 'yahoo.com', 'ebay.com',
            'abc.com', 'cnn.com', 'bbc.com', 'nytimes.com'
        ]

        # Keep only the original 53 features
        self.feature_names = [
            # Basic URL Structure Features
            'num_dots', 'num_hyphens', 'num_underscores', 'num_percent', 'num_slashes',
            'num_equal_signs', 'num_semicolons', 'num_ampersands', 'num_exclamations',
            'num_spaces', 'num_www', 'num_com', 'num_dollar_signs',
            
            # Additional Features
            'num_plus_signs', 'num_asterisks', 'num_hashtags', 'num_colons',
            'num_commas', 'num_question_marks', 'num_brackets', 'num_parentheses',
            'has_unicode', 'has_punycode', 'has_data_uri', 'has_file_extension',
            'has_brand_name', 'has_sensitive_terms', 'has_numeric_chars',
            'has_mixed_chars', 'protocol_count', 'subdomain_depth',
            'path_depth', 'url_entropy', 'domain_entropy',
            'path_entropy', 'query_entropy', 'fragment_entropy',
            
            # Length-based Features
            'url_length', 'domain_length', 'path_length', 'query_length',
            'fragment_length', 'avg_domain_token_length', 'max_domain_token_length',
            'avg_path_token_length', 'max_path_token_length', 'suspicious_tld_count',
            'suspicious_words_count', 'has_ip_address', 'has_at_symbol',
            'has_double_slash', 'has_suspicious_port', 'domain_token_count'
        ]

    def extract_features(self, url):
        # Initialize features
        features = {name: 0 for name in self.feature_names}
        
        # Parse URL components
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            fragment = parsed.fragment
        except Exception:
            domain = ''
            path = ''
            query = ''
            fragment = ''

        # Basic character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_percent'] = url.count('%')
        features['num_slashes'] = url.count('/')
        features['num_equal_signs'] = url.count('=')
        features['num_semicolons'] = url.count(';')
        features['num_ampersands'] = url.count('&')
        features['num_exclamations'] = url.count('!')
        features['num_spaces'] = url.count(' ')
        features['num_www'] = url.count('www')
        features['num_com'] = url.count('com')
        
        # Length-based features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        features['fragment_length'] = len(fragment)
        
        # Token-based features
        domain_tokens = domain.split('.')
        path_tokens = [t for t in path.split('/') if t]
        
        features['domain_token_count'] = len(domain_tokens)
        if domain_tokens:
            features['avg_domain_token_length'] = sum(len(t) for t in domain_tokens) / len(domain_tokens)
            features['max_domain_token_length'] = max(len(t) for t in domain_tokens)
        
        if path_tokens:
            features['avg_path_token_length'] = sum(len(t) for t in path_tokens) / len(path_tokens)
            features['max_path_token_length'] = max(len(t) for t in path_tokens)
        
        # Security-related features
        features['suspicious_tld_count'] = sum(domain.endswith(tld) for tld in self.suspicious_tlds)
        features['suspicious_words_count'] = sum(word in url.lower() for word in self.suspicious_words)
        features['has_ip_address'] = int(bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)))
        features['has_at_symbol'] = int('@' in url)
        features['has_double_slash'] = int('//' in path)
        features['has_suspicious_port'] = int(bool(re.search(r':\d{4,5}(?![0-9])', url)))

        # Convert to list in consistent order
        feature_list = [features[name] for name in self.feature_names]
        return np.array(feature_list)

    def _check_typo_in_domain(self, domain):
        # Check for common typos in domain names
        common_typos = {
            'gogle': 'google',
            'facebok': 'facebook',
            'amazn': 'amazon',
            'microsft': 'microsoft',
            'appl': 'apple',
            'yutube': 'youtube',
            'twiter': 'twitter',
            'linkdin': 'linkedin',
            'instagrm': 'instagram',
            'githb': 'github',
            'spotfy': 'spotify',
            'wikipdia': 'wikipedia',
            'redit': 'reddit',
            'yahooo': 'yahoo',
            'ebayy': 'ebay',
            'abcc': 'abc',
            'cnnn': 'cnn',
            'bbcc': 'bbc',
            'nytimess': 'nytimes'
        }
        
        domain_lower = domain.lower()
        for typo, correct in common_typos.items():
            if typo in domain_lower:
                return 1
        return 0

    def _is_legitimate_domain(self, domain):
        domain_lower = domain.lower()
        return int(any(legit_domain in domain_lower for legit_domain in self.legitimate_domains))

    def _check_suspicious_subdomain(self, domain):
        suspicious_subdomains = ['login', 'signin', 'verify', 'secure', 'account', 'banking']
        return int(any(subdomain in domain.lower() for subdomain in suspicious_subdomains))

    def _check_suspicious_path(self, path):
        suspicious_paths = ['login', 'signin', 'verify', 'secure', 'account', 'banking', 'password']
        return int(any(susp_path in path.lower() for susp_path in suspicious_paths))

    def _check_suspicious_query(self, query):
        suspicious_queries = ['login', 'signin', 'verify', 'secure', 'account', 'banking', 'password']
        return int(any(susp_query in query.lower() for susp_query in suspicious_queries))

    def _check_suspicious_fragment(self, fragment):
        suspicious_fragments = ['login', 'signin', 'verify', 'secure', 'account', 'banking', 'password']
        return int(any(susp_fragment in fragment.lower() for susp_fragment in suspicious_fragments))

    def _calculate_domain_trust_score(self, domain):
        score = 0
        domain_lower = domain.lower()
        
        # Check for legitimate domains
        if any(legit_domain in domain_lower for legit_domain in self.legitimate_domains):
            score += 3
            
        # Check for suspicious TLDs
        if any(domain_lower.endswith(tld) for tld in self.suspicious_tlds):
            score -= 2
            
        # Check for typos
        if self._check_typo_in_domain(domain):
            score -= 2
            
        # Check for suspicious subdomains
        if self._check_suspicious_subdomain(domain):
            score -= 1
            
        return score

    def _calculate_url_trust_score(self, url):
        score = 0
        url_lower = url.lower()
        
        # Check for suspicious words
        score -= sum(word in url_lower for word in self.suspicious_words)
        
        # Check for special characters
        score -= url.count('%') * 0.5
        score -= url.count('@') * 1
        score -= url.count('//') * 0.5
        
        # Check for length
        if len(url) > 100:
            score -= 1
            
        return score