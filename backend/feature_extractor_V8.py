import os
import re
import sys
import math
import signal
import logging
import hashlib
import subprocess
import base64
import pandas as pd
import magic  # python-magic
from collections import Counter
from functools import partial

# Optional peepdf imports
try:
    from peepdf.PDFCore import PDFParser, PDFIndirectObject
    PEEPDF_AVAILABLE = True
except ImportError:
    PEEPDF_AVAILABLE = False
    PDFParser = None
    PDFIndirectObject = None
    logging.warning("peepdf not installed. Advanced PDF parsing is unavailable.")

# ----------------------------------
# Logging Configuration
# ----------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def extract_features(pdf_path):
    logging.info(f"Starting feature extraction for: {pdf_path}")

    try:
        output = run_pdfid(pdf_path)  # Example of a subprocess call
        logging.info("PDFiD analysis completed.")

        features = parse_pdfid_output(output)
        logging.info("Feature extraction completed successfully.")

        return features
    except Exception as e:
        logging.error(f"Feature extraction failed: {str(e)}")
        return {}

# ----------------------------------
# Entropy Calculation
# ----------------------------------

def compute_entropy(data):
    """Calculate Shannon entropy of a given byte sequence."""
    if not data:
        return 0  # Avoid division by zero
    
    counter = Counter(data)
    total_bytes = len(data)
    
    entropy = -sum((count / total_bytes) * math.log2(count / total_bytes)
                   for count in counter.values())
    
    return entropy

# ----------------------------------
# PDFiD Handling
# ----------------------------------

def run_pdfid(pdf_path, pdfid_script_path="pdfid.py", timeout=30):
    """
    Runs pdfid.py on a given PDF file and returns the stdout text.
    If pdfid.py is not found or times out, we return an empty string.
    
    :param pdf_path: Path to PDF file
    :param pdfid_script_path: Path or filename for pdfid.py
    :param timeout: Timeout in seconds
    :return: pdfid.py stdout (str) or empty string on error
    """
    try:
        result = subprocess.run(
            ["python3", pdfid_script_path, "-a", pdf_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            logging.warning(f"PDFiD failed for {pdf_path}: {result.stderr}")
            return ""
        return result.stdout
    except subprocess.TimeoutExpired:
        logging.warning(f"PDFiD timed out for {pdf_path} after {timeout} seconds.")
        return ""
    except FileNotFoundError:
        logging.warning(f"pdfid.py not found. Skipping PDFiD for {pdf_path}.")
        return ""
    except Exception as e:
        logging.warning(f"PDFiD encountered error for {pdf_path}: {e}")
        return ""

def parse_pdfid_output(output):
    """
    Parses PDFiD output text and extracts numeric counts for various keys:
      /JS, /OpenAction, /AA, /AcroForm, /URI, /EmbeddedFile, /Launch, /ObjStm
    
    :param output: PDFiD output (string)
    :return: dict with integer counts for each key
    """
    features = {
        '/JS': 0,
        '/OpenAction': 0,
        '/AA': 0,
        '/AcroForm': 0,
        '/URI': 0,
        '/EmbeddedFile': 0,
        '/Launch': 0,
        '/ObjStm': 0
    }
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        # Typical line: "/JS                     2"
        for key in features:
            if line.startswith(key + " "):
                parts = line.split()
                # e.g. parts[0] = "/JS", parts[1] = "2"
                if len(parts) >= 2 and parts[1].isdigit():
                    features[key] = int(parts[1])
                break  # move to next line once matched
    return features

# ----------------------------------
# PDF-PARSER
# ----------------------------------

def extract_pdf_parser_features(pdf_path):
    """Runs pdf-parser.py to extract OpenActions, JavaScript, and suspicious object contents."""

    pdf_parser_cmd = ["python3", "pdf-parser.py", "-a", pdf_path]
    result = subprocess.run(pdf_parser_cmd, capture_output=True, text=True)

    output = result.stdout.lower()

    pdf_parser_features = {
        "contains_openaction": 1 if "openaction" in output else 0,
        "contains_aa": 1 if "/aa" in output else 0,
        "contains_launch": 1 if "/launch" in output else 0,
        "contains_alert": 1 if "app.alert" in output else 0,
        "contains_urls": output.count("/uri")
    }

    # Extract object numbers for OpenAction, JavaScript, and Launch actions
    suspicious_objects = []
    for line in output.split("\n"):
        match = re.search(r"obj\s+(\d+)\s+0", line)  # Finds "obj 12 0"
        if match:
            obj_id = match.group(1)
            suspicious_objects.append(obj_id)

    # Extract the content of suspicious objects
    object_details = {}
    for obj in suspicious_objects:
        obj_cmd = ["pdf-parser.py", "-o", obj, "-f", pdf_path]
        obj_result = subprocess.run(obj_cmd, capture_output=True, text=True)
        object_details[f"object_{obj}"] = obj_result.stdout.strip()

    pdf_parser_features["suspicious_objects"] = object_details
    return pdf_parser_features


# ----------------------------------
# Raw Byte Analysis
# ----------------------------------

def analyze_raw_bytes(pdf_path, chunk_size=1024*1024):
    """
    Simple raw-byte analysis with chunked reading:
      - Check presence of /JS, /OpenAction, /AcroForm
      - Count occurrences of 'stream' and 'obj'
    
    Returns a dictionary of these features.
    """
    has_js = 0
    has_openaction = 0
    has_acroform = 0
    stream_count = 0
    obj_count = 0

    try:
        with open(pdf_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                # Has at least one /JS?
                if b'/JS' in chunk:
                    has_js = 1
                # Has at least one /OpenAction?
                if b'/OpenAction' in chunk:
                    has_openaction = 1
                # Has at least one /AcroForm?
                if b'/AcroForm' in chunk:
                    has_acroform = 1
                
                # Count global occurrences
                stream_count += chunk.count(b'stream')
                obj_count += chunk.count(b'obj')
    except Exception as e:
        logging.warning(f"Error reading {pdf_path} for raw byte analysis: {e}")

    return {
        'has_javascript_marker': has_js,
        'has_openaction_marker': has_openaction,
        'has_acroform_marker': has_acroform,
        'num_streams': stream_count,
        'num_objs': obj_count
    }

# ----------------------------------
# JavaScript Extraction and Analysis
# ----------------------------------

def analyze_javascript(js_code):
    """Detect suspicious patterns in JavaScript."""
    js_features = {
        'contains_eval': int(b'eval(' in js_code),
        'contains_unescape': int(b'unescape(' in js_code),
        'contains_document_write': int(b'document.write(' in js_code),
        'contains_x_encoding': int(b'\\x' in js_code),  # Hex encoding
        'contains_base64': int(b'base64' in js_code.lower()),
        'contains_network_calls': int(b'XMLHttpRequest' in js_code or b'ActiveXObject' in js_code),
        'js_entropy': 0  # Ensure entropy is always initialized
    }

    try:
        js_features['js_entropy'] = compute_entropy(js_code)
    except Exception as e:
        logging.warning(f"Error computing entropy for JavaScript block: {e}")
        js_features['js_entropy'] = 0  # Default to 0 in case of failure

    return js_features


def extract_javascript(pdf_path):
    """Identify JavaScript blocks and analyze their content."""
    js_features = {
        'num_js_blocks': 0,
        'js_entropy_avg': 0,
        'js_entropy': 0,  # Explicitly add js_entropy to avoid KeyError
        'contains_eval': 0,
        'contains_unescape': 0,
        'contains_document_write': 0,
        'contains_x_encoding': 0,
        'contains_base64': 0,
        'contains_network_calls': 0
    }

    js_pattern = re.compile(rb'/JS\s*\((.*?)\)', re.DOTALL)

    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
    except Exception as e:
        logging.warning(f"Error reading {pdf_path} for JavaScript extraction: {e}")
        return js_features  # Return initialized values if file read fails

    matches = js_pattern.findall(content)

    if matches:
        js_features['num_js_blocks'] = len(matches)  # Properly count multiple JS occurrences
        entropy_values = []

        for js_block in matches:
            js_analysis = analyze_javascript(js_block)

            # Ensure 'js_entropy' is always in js_analysis
            js_analysis.setdefault('js_entropy', 0)

            # Accumulate only keys that exist in js_features
            for key in js_analysis:
                if key in js_features:  # Only update known keys
                    js_features[key] += js_analysis[key]

            entropy_values.append(js_analysis['js_entropy'])

        # Compute average JS entropy safely
        if entropy_values:
            js_features['js_entropy_avg'] = sum(entropy_values) / len(entropy_values)

    return js_features



# ----------------------------------
# Object Tree Depth Calculation (peepdf)
# ----------------------------------

def get_object_depth(pdf_object, current_depth=1):
    """Recursively calculate the depth of PDF objects."""
    if not hasattr(pdf_object, 'references') or not pdf_object.references:
        return current_depth

    return max(get_object_depth(ref, current_depth + 1) for ref in pdf_object.references)

def extract_peepdf_features(pdf_path):
    """Extract peepdf-based structural features, including object tree depth."""
    if not PEEPDF_AVAILABLE:
        return {
            'peepdf_parsed': 0,
            'object_count': 0,
            'encrypted_count': 0,
            'suspicious_streams': 0,
            'max_obj_depth': 0,
            'avg_obj_depth': 0
        }
    
    peepdf_features = {
        'peepdf_parsed': 0,
        'object_count': 0,
        'encrypted_count': 0,
        'suspicious_streams': 0,
        'max_obj_depth': 0,
        'avg_obj_depth': 0
    }

    try:
        parser = PDFParser()
        ret, pdf_doc = parser.parse(pdf_path, forceMode=True)

        if pdf_doc:
            peepdf_features['peepdf_parsed'] = 1
            objects = list(pdf_doc.body.values())

            obj_depths = []
            for obj in objects:
                depth = get_object_depth(obj)
                obj_depths.append(depth)

            peepdf_features['object_count'] = len(objects)
            peepdf_features['max_obj_depth'] = max(obj_depths) if obj_depths else 0
            peepdf_features['avg_obj_depth'] = sum(obj_depths) / len(obj_depths) if obj_depths else 0

    except Exception as e:
        logging.warning(f"Skipping {pdf_path}: Peepdf failed due to {e}")

    return peepdf_features

# ----------------------------------
# Ratio-Based Feature Engineering
# ----------------------------------

def compute_ratios(features):
    """Compute additional ratio-based features."""
    features['streams_per_object'] = (features['num_streams'] / features['num_objs']) if features['num_objs'] > 0 else 0
    features['encrypted_ratio'] = (features['encrypted_count'] / features['object_count']) if features['object_count'] > 0 else 0
    return features


# ----------------------------------
# Shellcode Detection
# ----------------------------------

def extract_shellcode(pdf_path):
    """
    Simple regex-based shellcode detection:
      - NOP sled
      - CALL with 4-byte offset
      - PUSH immediate
      - INT3 sequence
    
    :return: Dict with shellcode presence
    """
    shellcode_features = {
        'has_shellcode': 0,
        'num_shellcode_patterns': 0
    }
    shellcode_patterns = [
        rb'\x90{2,}',          # 2+ consecutive 0x90 (NOP)
        rb'\xE8[\x00-\xFF]{4}',# CALL
        rb'\x68[\x00-\xFF]{4}',# PUSH imm
        rb'\xCC{2,}',          # multiple INT3
    ]

    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
    except Exception as e:
        logging.warning(f"Error reading {pdf_path} for shellcode detection: {e}")
        return shellcode_features

    total_matches = 0
    for pattern in shellcode_patterns:
        matches = re.findall(pattern, content)
        if matches:
            total_matches += len(matches)
    if total_matches > 0:
        shellcode_features['has_shellcode'] = 1
        shellcode_features['num_shellcode_patterns'] = total_matches
    
    return shellcode_features

# ----------------------------------
# Phishing Indicators
# ----------------------------------

def extract_phishing_indicators(pdf_path):
    """
    Search for URLs (http:// or https://) and check if they match known suspicious keywords.
    
    :return: Dict with phishing-related features
    """
    phishing_features = {
        'num_urls': 0,
        'has_known_phishing_url': 0
    }
    url_pattern = re.compile(rb'https?://[^\s")>]+', re.IGNORECASE)

    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
    except Exception as e:
        logging.warning(f"Error reading {pdf_path} for phishing detection: {e}")
        return phishing_features

    urls = url_pattern.findall(content)
    phishing_features['num_urls'] = len(urls)

    # Placeholder: check if "phishing" or "suspicious" is in the URL
    for url in urls:
        if b'phishing' in url.lower() or b'suspicious' in url.lower():
            phishing_features['has_known_phishing_url'] = 1
            break

    return phishing_features

# ----------------------------------
# peepdf Parsing (Optional)
# ----------------------------------

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("peepdf parsing took too long")

import logging
import signal
import subprocess

from peepdf.PDFCore import PDFParser, PDFIndirectObject
PDFID_PATH = os.path.abspath("pdfid.py")

class TimeoutException(Exception):
    pass

def is_potentially_malicious(pdf_path):
    """
    Quick (optional) scan with pdfid.py to check if the PDF has OpenAction, Launch, JavaScript, or EmbeddedFiles.
    If it does, you might choose to skip parsing with peepdf or handle differently.
    """
    try:
        pdfid_output = subprocess.run(["python3", "pdfid.py", pdf_path], capture_output=True, text=True, timeout=30)
        pdfid_results = pdfid_output.stdout.lower()
        
        # If your security policy says "skip anything suspicious":
        if any(keyword in pdfid_results for keyword in ["/openaction", "/launch", "/javascript", "/embeddedfile"]):
            logging.warning(f"Skipping {pdf_path}: contains OpenAction/Launch/JavaScript/EmbeddedFile.")
            return True
    except Exception as e:
        logging.warning(f"Failed to check {pdf_path} with pdfid: {e}")
    
    return False

def extract_peepdf_features(pdf_path, parse_timeout=30, skip_on_suspicious=False):
    """
    Use peepdf to parse and extract advanced PDF structure info, while handling potentially
    malicious files in a safer way.

    :param pdf_path: Path to the PDF file.
    :param parse_timeout: Timeout (seconds) for peepdf parsing.
    :param skip_on_suspicious: If True, skip parsing files flagged by 'is_potentially_malicious()'.
    :return: Dictionary with peepdf-based features or a skip indicator.
    """
    # Optional: If you want to skip malicious PDFs entirely
    if skip_on_suspicious and is_potentially_malicious(pdf_path):
        return {
            'skipped_due_to_risk': 1,
            'peepdf_parsed': 0,
            'suspicious_streams': 0,
            'object_count': 0,
            'encrypted_count': 0,
            'skipped_due_to_timeout': 0,
            'skipped_due_to_error': 0
        }

    peepdf_features = {
        'skipped_due_to_risk': 0,
        'peepdf_parsed': 0,
        'suspicious_streams': 0,
        'object_count': 0,
        'encrypted_count': 0,
        'skipped_due_to_timeout': 0,
        'skipped_due_to_error': 0,
    }

    # Set up the timeout signal
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(parse_timeout)  # e.g., 30 seconds

    try:
        pdf_parser = PDFParser()
        ret, pdf = pdf_parser.parse(pdf_path, forceMode=True)

        if pdf is not None:
            peepdf_features['peepdf_parsed'] = 1
            total_obj_count = 0
            suspicious_streams = 0
            encrypted_count = 0

            # Handle object extraction safely
            for xref_obj in pdf.body:
                if not hasattr(xref_obj, 'objects'):
                    continue  # No objects here

                xref_objects = xref_obj.objects

                if isinstance(xref_objects, dict):
                    # Old-style dictionary of objects
                    for obj_id, pdf_object in xref_objects.items():
                        total_obj_count += 1
                        if isinstance(pdf_object, PDFIndirectObject):
                            pdf_object = getattr(pdf_object, "object", None)  # Avoid missing attribute errors
                        if pdf_object:
                            if getattr(pdf_object, 'isCompressed', False):
                                suspicious_streams += 1
                            if getattr(pdf_object, 'isEncrypted', False):
                                encrypted_count += 1

                elif isinstance(xref_objects, list):
                    # Newer-style list of objects
                    for pdf_object in xref_objects:
                        total_obj_count += 1
                        if isinstance(pdf_object, PDFIndirectObject):
                            pdf_object = getattr(pdf_object, "object", None)  # Avoid missing attribute errors
                        if pdf_object:
                            if getattr(pdf_object, 'isCompressed', False):
                                suspicious_streams += 1
                            if getattr(pdf_object, 'isEncrypted', False):
                                encrypted_count += 1

                else:
                    logging.warning(f"Unexpected xref_obj.objects type: {type(xref_objects)}")

            peepdf_features['object_count'] = total_obj_count
            peepdf_features['suspicious_streams'] = suspicious_streams
            peepdf_features['encrypted_count'] = encrypted_count

        signal.alarm(0)  # Disable alarm if successful

    except TimeoutException:
        logging.warning(f"Skipping {pdf_path}: peepdf took too long to parse.")
        peepdf_features['skipped_due_to_timeout'] = 1

    except AttributeError as e:
        logging.error(f"Skipping {pdf_path}: Peepdf attribute error: {e}")
        peepdf_features['skipped_due_to_error'] = 1

    except Exception as e:
        logging.warning(f"Skipping {pdf_path}: Peepdf failed due to {e}")
        peepdf_features['skipped_due_to_error'] = 1

    return peepdf_features

# ----------------------------------
# Main Feature Extraction
# ----------------------------------

def extract_features(pdf_path, pdfid_script_path="pdfid.py"):
    """
    Master function that orchestrates all sub-analyses:
      1) Basic file metadata
      2) PDFiD-based keyword counts
      3) Raw byte markers
      4) JavaScript extraction and analysis
      5) Shellcode detection
      6) Phishing indicators
      7) peepdf structural analysis
      8) Entropy analysis for obfuscation detection
      9) Object depth tracking
     10) Ratio-based feature calculations
    
    Returns a dict of all these features. 
    """
    features = {}

    # File metadata
    features['file_name'] = os.path.basename(pdf_path)
    try:
        with open(pdf_path, 'rb') as f:
            data = f.read()
        features['file_size'] = len(data)
        features['sha256'] = hashlib.sha256(data).hexdigest()
        features['file_entropy'] = compute_entropy(data)  # Compute file-level entropy
    except Exception as e:
        logging.warning(f"Error reading {pdf_path} for hashing/size: {e}")
        features['file_size'] = -1
        features['sha256'] = ""
        features['file_entropy'] = 0

    # magic file type
    try:
        features['file_type'] = magic.from_file(pdf_path)
    except Exception as e:
        logging.warning(f"Error determining file type for {pdf_path}: {e}")
        features['file_type'] = "unknown"

    # Simple label placeholder (1 if 'malicious' in path)
    features['label'] = 1 if 'malicious' in pdf_path.lower() else 0

    # 1) PDFiD Analysis
    pdfid_text = run_pdfid(pdf_path, pdfid_script_path=pdfid_script_path)
    pdfid_features = parse_pdfid_output(pdfid_text)
    for k, v in pdfid_features.items():
        features['pdfid_' + k.strip('/')] = v
    features['pdfid_output_empty'] = 1 if not pdfid_text else 0

    # 2) Raw byte analysis
    features.update(analyze_raw_bytes(pdf_path))

    # 3) JavaScript extraction and content analysis
    features.update(extract_javascript(pdf_path))

    # 4) Shellcode detection
    features.update(extract_shellcode(pdf_path))

    # 5) Phishing indicators
    features.update(extract_phishing_indicators(pdf_path))

    # 6) peepdf structural analysis (including object depth tracking)
    features.update(extract_peepdf_features(pdf_path, parse_timeout=30))

    # 7) Compute additional ratio-based features
    features = compute_ratios(features)

    return features


# ----------------------------------
# Directory Processing
# ----------------------------------

def process_directory(input_dir, output_file, pdfid_script_path="pdfid.py", use_multiprocessing=False):
    """
    Recursively walk through input_dir, extract features for each PDF, and save to CSV.
    Optionally uses multiprocessing to speed up analysis.
    """
    pdf_paths = []
    for root, dirs, files in os.walk(os.path.expanduser(input_dir)):
        for fname in files:
            if fname.lower().endswith('.pdf'):
                pdf_paths.append(os.path.join(root, fname))

    logging.info(f"Found {len(pdf_paths)} PDF files in {input_dir}.")

    if use_multiprocessing:
        import multiprocessing
        with multiprocessing.Pool() as pool:
            func = partial(extract_features, pdfid_script_path=pdfid_script_path)
            all_features = pool.map(func, pdf_paths)
    else:
        all_features = []
        for path in pdf_paths:
            logging.info(f"Processing: {path}")
            feats = extract_features(path, pdfid_script_path=pdfid_script_path)
            all_features.append(feats)

    # Save to CSV
    df = pd.DataFrame(all_features)
    df.to_csv(output_file, index=False)
    logging.info(f"Saved {len(df)} records to {output_file}")

# ----------------------------------
# Example Usage
# ----------------------------------

if __name__ == "__main__":
    input_dir = "~/secure_malware_samples"
    output_file = "malware_features_V8.csv"
    
    # If pdfid.py is in the same folder or your PATH, you can pass just "pdfid.py"
    pdfid_path = "pdfid.py"
    
    # Decide if you want parallel processing (helpful with many PDFs)
    process_directory(
        input_dir=input_dir,
        output_file=output_file,
        pdfid_script_path=pdfid_path,
        use_multiprocessing=False
    )