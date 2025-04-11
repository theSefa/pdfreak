#!/usr/bin/env python3
"""
verify_model.py - Script to verify model saving/loading and feature ordering
"""

import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from feature_extractor_V8 import extract_features

def debug_feature_values(features):
    """Print detailed information about feature types and values."""
    print("\nFeature Debug Information:")
    print("-" * 50)
    for feature, value in features.items():
        print(f"Feature: {feature}")
        print(f"  Value: {value}")
        print(f"  Type: {type(value)}")
        try:
            float_val = float(value)
            print(f"  Converts to float: Yes ({float_val})")
        except (ValueError, TypeError):
            print(f"  Converts to float: No")
        print("-" * 30)

def safe_convert_to_float(value):
    """Safely convert a value to float, returning 0.0 if conversion fails."""
    try:
        return float(value)
    except (ValueError, TypeError):
        print(f"Warning: Could not convert value '{value}' to float. Using 0.0")
        return 0.0

def load_and_verify_model(model_path, csv_path=None):
    """Load model and verify it with training data."""
    print("=== Model Verification Test ===")
    
    # Load the model
    print("\nLoading model...")
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        
        # Print model pipeline steps
        print("\nModel Pipeline Steps:")
        for step_name, step in model.named_steps.items():
            print(f"- {step_name}: {type(step).__name__}")
        
        # Get feature names if available
        if hasattr(model, 'feature_names_in_'):
            print("\nExpected feature names:")
            print(model.feature_names_in_)
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

    return model

def test_feature_extraction(model, pdf_path):
    """Test feature extraction and prediction on a specific PDF."""
    print(f"\nTesting feature extraction for: {pdf_path}")
    
    try:
        # Extract features
        raw_features = extract_features(str(pdf_path))
        
        # Debug print all features and their types
        debug_feature_values(raw_features)
        
        # Convert features to numeric values
        numeric_features = {}
        for key, value in raw_features.items():
            numeric_features[key] = safe_convert_to_float(value)
        
        # Create feature array
        feature_names = list(numeric_features.keys())
        feature_values = [numeric_features[name] for name in feature_names]
        feature_array = np.array([feature_values])
        
        print("\nFeature array shape:", feature_array.shape)
        print("Feature names:", feature_names)
        
        # Make prediction
        try:
            pred = model.predict(feature_array)[0]
            prob = model.predict_proba(feature_array)[0]
            
            print(f"\nPrediction: {'Malicious' if pred == 1 else 'Benign'}")
            print(f"Confidence: {max(prob):.4f}")
            
        except Exception as e:
            print(f"\nError during prediction: {str(e)}")
            print("Feature array shape:", feature_array.shape)
            print("Feature values:", feature_array)
            
    except Exception as e:
        print(f"Error during feature extraction: {str(e)}")

if __name__ == "__main__":
    MODEL_PATH = "model_artifacts/model_20250218_161645.pkl"
    TEST_PDF = "/Users/Sefa/Documents/BRUNEL/FINAL YEAR/CS3072_FYP/AZURE_VM/benign/10089434.pdf"  # Replace with your test PDF path
    
    # Load and verify model
    model = load_and_verify_model(MODEL_PATH)
    
    if model is not None and Path(TEST_PDF).exists():
        test_feature_extraction(model, TEST_PDF)
    else:
        print("Could not proceed with testing due to missing model or test file.")