import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import pickle
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.feature_extractor import URLFeatureExtractor

def train_phishing_model(dataset_path, model_output_path):
    # Load dataset
    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    # Check if 'label' column exists
    if 'label' not in df.columns:
        raise ValueError(f"'label' column not found. Available columns: {', '.join(df.columns)}")
    
    # Preprocess features
    print("Preprocessing features...")
    
    # Drop non-feature columns
    X = df.drop(columns=['FILENAME', 'URL', 'label'])
    y = df['label']
    
    # Convert categorical columns to numeric
    categorical_columns = X.select_dtypes(include=['object']).columns
    for column in categorical_columns:
        # Replace NaN values with a placeholder
        X[column] = X[column].fillna('unknown')
        # Convert to numeric using LabelEncoder
        le = LabelEncoder()
        X[column] = le.fit_transform(X[column])
    
    # Convert any remaining non-numeric values to 0
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Split dataset
    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Ensure column alignment
    X_train, X_test = X_train.align(X_test, join='left', axis=1, fill_value=0)
    
    # Train model
    print("Training Random Forest model...")
    print(f"Number of features: {X_train.shape[1]}")
    print(f"Training samples: {X_train.shape[0]}")
    print(f"Testing samples: {X_test.shape[0]}")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    
    # Verify data types
    print("\nFeature data types:")
    print(X_train.dtypes.value_counts())
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    print("\nModel Performance:")
    print(classification_report(y_test, y_pred))
    
    # Save model and feature names
    print(f"\nSaving model to {model_output_path}")
    with open(model_output_path, 'wb') as f:
        pickle.dump(model, f)
    
    feature_names = X.columns.tolist()
    feature_path = os.path.join(os.path.dirname(model_output_path), 'feature_names.pkl')
    with open(feature_path, 'wb') as f:
        pickle.dump(feature_names, f)
    print(f"Saved feature names to {feature_path}")
    
    return model

if __name__ == '__main__':
    dataset_path = '../data/dataset_full.csv'
    model_output_path = '../model/phishing_model.pkl'
    
    # Create model directory if needed
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    
    # Train and save model
    model = train_phishing_model(dataset_path, model_output_path)