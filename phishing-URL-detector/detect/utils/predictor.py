import pickle
import numpy as np
import pandas as pd
from .feature_extractor import URLFeatureExtractor

class PhishingPredictor:
    def __init__(self, model_path, feature_names_path=None):
        self.feature_extractor = URLFeatureExtractor()
        
        # Load the trained model
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        # Load feature names if provided
        self.feature_names = None
        if feature_names_path:
            with open(feature_names_path, 'rb') as f:
                self.feature_names = pickle.load(f)
    
    def predict_url(self, url):
        try:
            # Extract features
            features = self.feature_extractor.extract_features(url)
            
            # Convert to DataFrame with feature names
            if self.feature_names is not None:
                features_df = pd.DataFrame([features], columns=self.feature_names)
            else:
                features_df = pd.DataFrame([features])
            
            # Get prediction and probability
            prediction = self.model.predict(features_df)[0]
            probability = np.max(self.model.predict_proba(features_df)[0])
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(probability),
                'status': 'success'
            }
            
        except Exception as e:
            return {
                'is_phishing': None,
                'confidence': None,
                'status': 'error',
                'error': str(e)
            }