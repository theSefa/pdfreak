#!/usr/bin/env python3
"""
use_pdf_model.py

Example usage script to:
1) Load the saved model pipeline (.pkl).
2) Load its JSON metadata with final feature names.
3) Extract features from a specified PDF file.
4) Convert those features to the correct order/format.
5) Run predict() and predict_proba() on the PDF to determine benign/malicious.

Adjust paths and file names as needed.
"""

import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from feature_extractor_V8 import extract_features  # Your custom feature extraction function

# -----------------------------
# 1) Specify Paths
# -----------------------------
MODEL_PATH = Path("model_artifacts/model_20250218_082549.pkl")
METADATA_PATH = Path("model_artifacts/model_metadata_20250218_082549.json")
PDF_FILE = Path("/Users/Sefa/Documents/BRUNEL/FINAL YEAR/CS3072_FYP/AZURE_VM/benign/10089434.pdf")  # <-- Adjust to your PDF

# -----------------------------
# 2) Load the Model & Metadata
# -----------------------------
def load_model_and_metadata(model_path, metadata_path):
    """
    Load a pre-trained model pipeline (via joblib) and associated metadata (JSON).
    Returns: (model, metadata_dict)
    """
    # Load the pipeline
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    model = joblib.load(model_path)

    # Load the metadata
    if not metadata_path.exists():
        raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
    with open(metadata_path, "r") as f:
        metadata = json.load(f)

    return model, metadata

# -----------------------------
# 3) Build a Feature Vector
# -----------------------------
def build_feature_vector(raw_features, final_feature_names):
    """
    Convert raw_features (dict) into a list of floats in the exact order
    specified by final_feature_names. If a feature is missing or non-numeric,
    default to 0.0.
    """
    data = []
    for feat in final_feature_names:
        raw_val = raw_features.get(feat, 0.0)
        try:
            data.append(float(raw_val))
        except (ValueError, TypeError):
            data.append(0.0)
    return data

# -----------------------------
# 4) Single-PDF Prediction
# -----------------------------
def predict_pdf(model, metadata, pdf_path):
    """
    Extract features from pdf_path, filter/format them to match the model's
    final features, then produce a prediction and probability.
    
    Returns a dict with 'prediction' and 'confidence' (among other info).
    """
    final_features = metadata["feature_names"]  # e.g., 14 columns

    # 1) Extract raw feature dict from the PDF
    raw_features = extract_features(str(pdf_path))  # function from feature_extractor_V8

    # 2) Convert raw_features to the correct order
    feature_vector = build_feature_vector(raw_features, final_features)
    feature_array = np.array([feature_vector])  # shape: (1, n_features)

    # 3) Make prediction
    pred = model.predict(feature_array)[0]
    proba = model.predict_proba(feature_array)[0]  # e.g., [p_class0, p_class1] for binary

    # For a binary classifier with labels 0=benign, 1=malicious:
    predicted_label = "Malicious" if pred == 1 else "Benign"
    confidence = float(proba[1] if pred == 1 else proba[0])

    return {
        "pdf_name": pdf_path.name,
        "prediction": predicted_label,
        "confidence": confidence,
        "raw_features": raw_features,
        "final_feature_vector": feature_vector
    }

# -----------------------------
# 5) Main Execution
# -----------------------------
if __name__ == "__main__":
    # 1) Load model + metadata
    model, metadata = load_model_and_metadata(MODEL_PATH, METADATA_PATH)
    print(f"Loaded model from: {MODEL_PATH}")
    print(f"Loaded metadata from: {METADATA_PATH}")
    print(f"Final features used: {metadata['feature_names']}")

    # 2) Predict a specific PDF file
    if not PDF_FILE.exists():
        print(f"ERROR: PDF file not found: {PDF_FILE}")
    else:
        result = predict_pdf(model, metadata, PDF_FILE)
        print("\n=== PREDICTION RESULT ===")
        print(f"File: {result['pdf_name']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.4f}")
        # If you want to see the raw or final features, you can print those as well:
        # print("Raw features:", result['raw_features'])
        # print("Final feature vector:", result['final_feature_vector'])
