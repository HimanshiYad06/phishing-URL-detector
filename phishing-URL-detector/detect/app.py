import streamlit as st
import pandas as pd
from utils.predictor import PhishingPredictor
from utils.virustotal import VirusTotalAPI
from utils.safebrowsing import SafeBrowsingAPI
import os

# Page config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme and modern look
st.markdown("""
<style>
    .stApp {
        background-color: #1E1E1E;
        color: #FFFFFF;
    }
    .stTextInput > div > div > input {
        background-color: #2D2D2D;
        color: #FFFFFF;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        border: none;
        padding: 10px 24px;
        width: 100%;
    }
    .success-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: rgba(76, 175, 80, 0.1);
        border: 1px solid #4CAF50;
    }
    .warning-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: rgba(255, 87, 34, 0.1);
        border: 1px solid #FF5722;
    }
    .danger-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: rgba(244, 67, 54, 0.1);
        border: 1px solid #F44336;
    }
    .info-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: rgba(33, 150, 243, 0.1);
        border: 1px solid #2196F3;
    }
    .vt-info {
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for scan history
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Title and description
st.title("🔒 Phishing URL Detector")
st.markdown("""Analyze URLs for phishing threats using advanced feature extraction, pattern analysis, and a trained Random Forest machine learning model. Enter a URL below to check its legitimacy.""")

# Load the model and APIs
@st.cache_resource
def load_resources():
    model_path = os.path.join('model', 'phishing_model.pkl')
    feature_names_path = os.path.join('model', 'feature_names.pkl')
    vt_api_key = "a207bfaf2f7e6a7e84db21bb0a2f8720f921be6aa13953142303cb92b3306388"
    gsb_api_key = "AIzaSyDasT0zXZrK2HiHxEoDb_-TjFfCXEXsajE"
    return {
        'predictor': PhishingPredictor(model_path, feature_names_path),
        'vt_api': VirusTotalAPI(vt_api_key),
        'gsb_api': SafeBrowsingAPI(gsb_api_key)
    }

try:
    resources = load_resources()
    predictor = resources['predictor']
    vt_api = resources['vt_api']
    gsb_api = resources['gsb_api']
    model_loaded = True
except Exception as e:
    st.error(f"Error loading resources: {str(e)}")
    model_loaded = False

# URL input
url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")

if st.button("Analyze URL") and url and model_loaded:
    with st.spinner("Analyzing URL..."):
        # Get ML prediction
        ml_result = predictor.predict_url(url)
        
        # Get VirusTotal results
        vt_result = vt_api.scan_url(url)
        
        # Get Google Safe Browsing results
        gsb_result = gsb_api.check_url(url)
        
        # Add to scan history
        st.session_state.scan_history.append({
            'url': url,
            'ml_is_phishing': ml_result['is_phishing'] if ml_result['status'] == 'success' else None,
            'ml_confidence': ml_result['confidence'] if ml_result['status'] == 'success' else None,
            'vt_status': vt_result['result']['status'] if vt_result['status'] == 'success' else None,
            'vt_is_phishing': vt_result['result']['is_phishing'] if vt_result['status'] == 'success' else None,
            'gsb_status': gsb_result['result']['threat_level'] if gsb_result['status'] == 'success' else None
        })
        
        # Display combined results
        if ml_result['status'] == 'success':
            st.markdown("### Machine Learning Analysis")
            
            # Get status from both sources
            vt_status = None
            gsb_status = None
            vt_data = None
            gsb_data = None
            
            if vt_result['status'] == 'success':
                vt_data = vt_result['result']
                vt_status = 'safe' if vt_data['status'] == 'clean' else 'unsafe'
            
            if gsb_result['status'] == 'success':
                gsb_data = gsb_result['result']
                gsb_status = 'safe' if gsb_data['threat_level'] == 'clean' else 'unsafe'
            
            # Determine combined status
            if vt_status == 'safe' and gsb_status == 'safe':
                combined_status = 'Safe'
                status_icon = '✅'
                box_class = 'success-box'
            elif vt_status == 'unsafe' and gsb_status == 'unsafe':
                combined_status = 'Malicious'
                status_icon = '🚫'
                box_class = 'danger-box'
            else:
                combined_status = 'Potentially Malicious'
                status_icon = '⚠️'
                box_class = 'warning-box'
            
            # Display combined status
            st.markdown(f"""
                <div class='{box_class}'>
                    <h3>{status_icon} {combined_status}</h3>
                    <p>Based on advanced feature extraction, pattern analysis, and a trained Random Forest machine learning model</p>
                </div>
            """, unsafe_allow_html=True)
            
            # Display detailed analysis
            if vt_result['status'] == 'success' and gsb_result['status'] == 'success':
                vt_data = vt_result['result']
                gsb_data = gsb_result['result']
                
                # Get status icon
                if combined_status == 'Safe':
                    status_icon = '✅'
                elif combined_status == 'Malicious':
                    status_icon = '🚫'
                else:
                    status_icon = '⚠️'
                
                # Get threats detected
                threats = []
                if gsb_data['threats']:
                    threats.extend(gsb_data['threats'])
                if vt_data['is_phishing']:
                    threats.append('Phishing')
                
                st.markdown(f"""
                    <div class='info-box'>
                        <p>{status_icon} Status: {combined_status}</p>
                        <p>Detection Rate: {vt_data['positives']}/{vt_data['total']} antivirus engines flagged this URL</p>
                        <p>Phishing Detection: {'Yes' if vt_data['is_phishing'] else 'No'}</p>
                        <p>Threats Detected: {', '.join(threats) if threats else 'None'}</p>
                        <p>Categories: {', '.join(vt_data['categories']) if vt_data['categories'] else 'None'}</p>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div class='info-box'>
                        <p>Error getting analysis results</p>
                    </div>
                """, unsafe_allow_html=True)

# Scan History
if st.session_state.scan_history:
    st.markdown("### Recent Scans")
    history_df = pd.DataFrame(st.session_state.scan_history)
    
    # Create combined status for history
    def get_combined_status(row):
        vt_safe = row['vt_status'] == 'clean'
        gsb_safe = row['gsb_status'] == 'clean'
        
        if pd.isna(row['vt_status']) or pd.isna(row['gsb_status']):
            return "❓ Unknown"
        elif vt_safe and gsb_safe:
            return "✅ Safe"
        elif not vt_safe and not gsb_safe:
            return "🚫 Malicious"
        else:
            return "⚠️ Potentially Malicious"
    
    history_df['ML Analysis'] = history_df.apply(get_combined_status, axis=1)
    
    st.dataframe(
        history_df[['url', 'ML Analysis']].tail(5),
        hide_index=True,
        use_container_width=True
    )