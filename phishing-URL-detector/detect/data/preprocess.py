import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def load_data(file_path):
    """Load the dataset from CSV file."""
    return pd.read_csv(file_path)

def clean_data(df):
    """Clean and preprocess the dataset."""
    # Remove duplicates
    df = df.drop_duplicates()
    
    # Handle missing values
    df = df.dropna()
    
    return df

def prepare_features(df):
    """Prepare features for model training."""
    # Add your feature preparation logic here
    # Example: Normalize numerical features, encode categorical variables
    return df

def split_dataset(X, y, test_size=0.2, random_state=42):
    """Split dataset into training and testing sets."""
    return train_test_split(X, y, test_size=test_size, random_state=random_state)

def main():
    # Load dataset
    df = load_data('dataset_full.csv')
    
    # Clean data
    df = clean_data(df)
    
    # Prepare features
    df = prepare_features(df)
    
    # Save processed dataset
    df.to_csv('processed_dataset.csv', index=False)

if __name__ == '__main__':
    main()