from fastapi import FastAPI, File, UploadFile, HTTPException
import shutil
import os
import pickle
import json
import numpy as np
import pandas as pd
from pathlib import Path
from feature_extractor_V8 import extract_features, extract_pdf_parser_features
import requests
import signal
import subprocess
import pyzipper
import uuid
import tempfile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

# Timeout handling
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Feature extraction took too long!")

signal.signal(signal.SIGALRM, timeout_handler)

def safe_extract_features(pdf_path):
    signal.alarm(60)  # Start timeout
    try:
        features = extract_features(pdf_path)
        signal.alarm(0)  # Reset timeout if successful
        return features
    except TimeoutException:
        raise HTTPException(status_code=500, detail="Feature extraction timed out.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {str(e)}")

# Initialize FastAPI app
app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True, mode=0o700)  # Restrictive permissions

# FAISS index path
FAISS_INDEX_PATH = "faiss_index_updated"

# ZIP password
ZIP_PASSWORD = "infected"

# Security settings
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB limit for decompressed files

# Load the model and its metadata
MODEL_DIR = "model_artifacts"
model_path = Path(MODEL_DIR) / "model_20250220_093453.pkl"
metadata_path = Path(MODEL_DIR) / "model_metadata_20250220_062542.json"

try:
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    with open(metadata_path, "r") as f:
        model_metadata = json.load(f)
    FINAL_FEATURES = model_metadata["feature_names"]
except FileNotFoundError as e:
    raise RuntimeError(f"Could not load model files: {e}")

# Load FAISS index at startup
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
vector_store = None

@app.on_event("startup")
async def startup_event():
    global vector_store
    try:
        vector_store = FAISS.load_local(FAISS_INDEX_PATH, embeddings, allow_dangerous_deserialization=True)
        print(f"Loaded FAISS index with {vector_store.index.ntotal} chunks (635 PDFs + MITRE data)")
    except Exception as e:
        print(f"Error loading FAISS index: {e}")
        raise Exception("Failed to load FAISS index")

def process_features(raw_features: dict) -> np.ndarray:
    """
    Convert raw feature dict into a NumPy array with the exact features
    and order the model expects (FINAL_FEATURES).
    Missing or non-numeric values default to 0.0.
    """
    df = pd.DataFrame(columns=FINAL_FEATURES)
    df.loc[0] = 0.0
    for key, val in raw_features.items():
        if key in df.columns:
            try:
                df.loc[0, key] = float(val)
            except (ValueError, TypeError):
                print(f"Warning: Could not convert '{key}' value '{val}' to float. Using 0.")
    feature_array = df.astype(float).values
    return feature_array

# Pydantic model for response
class AnalysisResponse(BaseModel):
    filename: str
    prediction: str
    confidence: float
    features: dict
    ai_analysis: str
    timestamp: str

import os
OLLAMA_API_URL = os.getenv("OLLAMA_HOST", "http://localhost:11434") + "/api/generate"

def query_mistral(features: dict, prediction: str, retrieved_chunk: str = None):
    """
    Sends extracted PDF features, binary prediction, and RAG-retrieved chunk to Mistral
    for malware analysis with MITRE ATT&CK mappings.
    """
    features_str = "\n".join([f"- {k}: {v}" for k, v in features.items()])
    context_section = ""
    if retrieved_chunk:
        context_section = f"""
    Context from Knowledge Base (635 PDFs or MITRE ATT&CK):
    {retrieved_chunk}
    """

    prompt = f"""
    You are a cybersecurity expert specializing in PDF malware analysis.
    Given the extracted PDF features and binary classification below, analyze the PDF and give the report without the instructional cues I provided to guide you.
    Also remember, if the PDF file is classified as Benign, there is no need for the risk assessment, possible malware type categorisation or mapping the MITRE ATT&CK Techniques!
    ---
     Extracted PDF Features:
    {features_str}

     **Binary Classification:**
    The PDF has been classified as {prediction}.

    {context_section}
    ---

    Step 1: Analyze Based on Classification and Features
    - The binary classification ({prediction}) indicates the initial assessment.
    - Use the features and context (if provided) to refine the analysis.

    Step 2: Provide the Following:
    - If the PDF is classified as **Benign** and features show no suspicious elements:
      -  This PDF appears to be clean with no signs of malicious activity.
      -  No further action is required.
    - If the PDF is classified as **Malicious** or features indicate potential malice:
      - Risk Assessment: (Low, Medium, or High)
      - Possible Malware Type: (Phishing, Exploit, Spyware, Ransomware, etc.)
      -  Key Indicators of Malicious Behavior:(Use bullet points)
      -  Recommended Security Actions: (Use numbered list)
      - Relevant MITRE ATT&CK Techniques:
        - List the **most relevant ATT&CK Tactics & Techniques**.
        - Provide the **ATT&CK technique ID** (e.g., T1059.001 for JavaScript Execution).
        - Explain how the attack technique applies to this PDF.

    """

    payload = {"model": "mistral", "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "Error generating response")
    except Exception as e:
        return f"LLM Error: {str(e)}"

@app.post("/analyze-upload", response_model=AnalysisResponse)
async def analyze_and_predict(file: UploadFile = File(...)):
    """
    Handles PDF or ZIP'd PDF uploads, extracts features, runs model prediction,
    integrates RAG with a specific query, and sends data for AI analysis.
    """
    try:
        # Validate file type
        is_zip = file.filename.lower().endswith(".zip")
        is_pdf = file.filename.lower().endswith(".pdf")
        if not (is_zip or is_pdf):
            raise HTTPException(status_code=400, detail="Invalid file format. Please upload a PDF or ZIP file.")

        # Check file size
        file_content = await file.read()
        if len(file_content) > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=400, detail=f"File size exceeds limit of {MAX_UPLOAD_SIZE / 1024 / 1024} MB")

        # Use a temporary directory for all file operations
        with tempfile.TemporaryDirectory(dir=UPLOAD_DIR) as temp_dir:
            # Save uploaded file with a unique filename
            unique_filename = f"{uuid.uuid4()}_{file.filename}"
            uploaded_file_path = Path(temp_dir) / unique_filename
            with open(uploaded_file_path, "wb") as buffer:
                buffer.write(file_content)

            # Create a subdirectory for extracted files
            extract_dir = Path(temp_dir) / "extracted"
            extract_dir.mkdir(exist_ok=True)

            # Initialize variables
            pdf_path = None

            try:
                # Handle ZIP extraction
                if is_zip:
                    # Check for Zip Slip and validate contents
                    with pyzipper.AESZipFile(uploaded_file_path) as zip_ref:
                        zip_ref.setpassword(ZIP_PASSWORD.encode())
                        # Validate file paths to prevent Zip Slip
                        extract_base = extract_dir.resolve()
                        for zip_info in zip_ref.infolist():
                            # Normalize the filename and resolve the target path
                            filename = Path(zip_info.filename).name  # Strip any path components
                            target_path = (extract_base / filename).resolve()
                            # Check if the resolved path is within the extract_base
                            if not str(target_path).startswith(str(extract_base)):
                                print(f"Zip Slip detected: {zip_info.filename} resolves to {target_path}")
                                raise HTTPException(status_code=400, detail=f"Invalid ZIP: Directory traversal detected (Zip Slip) in file {zip_info.filename}")
                            # Estimate decompressed size to prevent zip bombs
                            if zip_info.file_size > MAX_DECOMPRESSED_SIZE:
                                raise HTTPException(status_code=400, detail=f"Decompressed file size exceeds limit of {MAX_DECOMPRESSED_SIZE / 1024 / 1024} MB")

                        # Extract the ZIP to the temporary extract_dir
                        zip_ref.extractall(extract_dir)

                    # Find the extracted PDF
                    pdf_found = False
                    for extracted_file in os.listdir(extract_dir):
                        if extracted_file.lower().endswith('.pdf'):
                            if pdf_found:
                                raise HTTPException(status_code=400, detail="ZIP file contains multiple PDFs; only one PDF is allowed.")
                            pdf_path = Path(extract_dir) / extracted_file
                            pdf_found = True
                    if not pdf_found:
                        raise HTTPException(status_code=400, detail="ZIP file does not contain a PDF.")
                else:
                    pdf_path = uploaded_file_path

                # Extract features
                raw_features = safe_extract_features(str(pdf_path))
                pdf_parser_features = extract_pdf_parser_features(str(pdf_path))
                combined_features = {**raw_features, **pdf_parser_features}

                # Convert to model-friendly format
                processed_features = process_features(combined_features)

                # Run model prediction
                prediction = model.predict(processed_features)[0]
                probability = model.predict_proba(processed_features)[0]  # [p(Benign), p(Malicious)]

                # Determine classification result
                is_malicious = prediction == 1
                prediction_label = "Malicious" if is_malicious else "Benign"
                confidence = float(probability[1]) if is_malicious else float(probability[0])

                # RAG: Construct a specific query based on features
                query_keywords = []
                suspicious_features_present = False

                # Strong indicators of malice
                if combined_features.get("has_shellcode", 0) == 1:
                    query_keywords.append("shellcode")
                    suspicious_features_present = True
                if combined_features.get("num_shellcode_patterns", 0) > 100:
                    if "shellcode" not in query_keywords:
                        query_keywords.append("shellcode")
                    suspicious_features_present = True
                if combined_features.get("has_known_phishing_url", 0) == 1:
                    query_keywords.append("phishing")
                    suspicious_features_present = True
                if combined_features.get("contains_eval", 0) == 1:
                    query_keywords.append("eval")
                    suspicious_features_present = True
                if combined_features.get("contains_base64", 0) == 1:
                    query_keywords.append("base64")
                    suspicious_features_present = True
                if combined_features.get("contains_network_calls", 0) == 1:
                    query_keywords.append("network")
                    suspicious_features_present = True
                if combined_features.get("contains_launch", 0) == 1:
                    query_keywords.append("launch")
                    suspicious_features_present = True
                if combined_features.get("contains_alert", 0) == 1:
                    query_keywords.append("alert")
                    suspicious_features_present = True

                # PDFiD markers
                if combined_features.get("pdfid_Launch", 0) == 1:
                    query_keywords.append("launch")
                    suspicious_features_present = True
                if combined_features.get("pdfid_EmbeddedFile", 0) == 1:
                    query_keywords.append("embedded file")
                    suspicious_features_present = True
                if combined_features.get("pdfid_OpenAction", 0) == 1:
                    query_keywords.append("openaction")
                    suspicious_features_present = True
                if combined_features.get("pdfid_JS", 0) == 1:
                    query_keywords.append("javascript")
                    suspicious_features_present = True

                # Secondary indicators
                if combined_features.get("num_urls", 0) > 0:
                    query_keywords.append("urls")
                    suspicious_features_present = True
                if combined_features.get("num_js_blocks", 0) > 0:
                    query_keywords.append("javascript")
                    suspicious_features_present = True
                if combined_features.get("file_entropy", 0) > 7.0:
                    query_keywords.append("obfuscation")
                    suspicious_features_present = True
                if combined_features.get("encrypted_ratio", 0) > 0:
                    query_keywords.append("encrypted")
                    suspicious_features_present = True
                if combined_features.get("suspicious_streams", 0) > 0:
                    query_keywords.append("suspicious streams")
                    suspicious_features_present = True

                # Determine query based on classification and features
                if is_malicious or suspicious_features_present:
                    if not query_keywords:
                        query_keywords.append("malicious behavior")
                else:
                    query_keywords.append("benign")

                # Join keywords into a single query string
                query = " ".join(set(query_keywords))  # Use set to avoid duplicates
                print(f"Generated query: {query}")

                # Retrieve chunk from FAISS
                retrieved_chunk = None
                try:
                    results = vector_store.similarity_search(query, k=1)
                    retrieved_chunk = results[0].page_content if results else None
                    print(f"Retrieved chunk for query '{query}': {retrieved_chunk}")
                except Exception as e:
                    print(f"Error retrieving chunk: {e}")

                # Send extracted features, prediction, and RAG chunk to Mistral
                ai_analysis = query_mistral(combined_features, prediction_label, retrieved_chunk)

                # Prepare final response
                result = {
                    "filename": file.filename,
                    "prediction": prediction_label,
                    "confidence": confidence,
                    "features": combined_features,
                    "ai_analysis": ai_analysis,
                    "timestamp": pd.Timestamp.now().isoformat()
                }

                return result

            finally:
                # Cleanup is handled by TemporaryDirectory
                pass

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.get("/model-info/")
async def model_info():
    """Returns metadata about the loaded model for UI display."""
    return {
        "model_name": "PDFreak AI",
        "version": model_metadata.get("model_version", "Unknown"),
        "feature_count": len(FINAL_FEATURES),
        "trained_on": model_metadata.get("training_timestamp", "N/A"),
        "features_used": FINAL_FEATURES
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)