# Phishing URL Detector

A machine learning-powered web application that detects potential phishing URLs in real-time using Streamlit.

## Features

- Real-time URL analysis
- Machine learning-based detection
- Modern dark-themed UI
- Confidence score for predictions
- Recent scan history
- Comprehensive URL feature extraction

## Setup

1. Create and activate virtual environment:
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On Unix or MacOS
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Train the model:
```bash
cd training
python train_model.py
```

4. Run the application:
```bash
streamlit run app.py
```

## Project Structure

- `app.py`: Main Streamlit application
- `utils/`: Utility functions
  - `feature_extractor.py`: URL feature extraction
  - `predictor.py`: Model prediction wrapper
- `training/`: Model training scripts
- `model/`: Trained model storage
- `data/`: Dataset storage

## Usage

1. Enter a URL in the input field
2. Click "Analyze URL"
3. View the prediction results and confidence score
4. Check recent scan history below

## Model Features

The model analyzes various URL characteristics including:
- URL length and structure
- Special character frequency
- Domain and subdomain analysis
- TLD reputation
- Path and parameter analysis
- Security indicators