from flask import Flask, request, jsonify, render_template
import hashlib
import requests
import os
import time

app = Flask(__name__)

# 🔑 Your VirusTotal API key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{}"

# Use a clean absolute path for the uploads folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def compute_hashes(filepath):
    """Compute MD5, SHA1, SHA256 of uploaded file with safe file handling."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception as e:
        print(f"Hashing error: {e}")
        return None, None, None

def check_hash_virustotal(sha256_hash):
    """Check if hash is already known to VirusTotal."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(VT_HASH_URL.format(sha256_hash), headers=headers)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"VT Hash Check Error: {e}")
    return None

def upload_to_virustotal(filepath):
    """Upload file to VirusTotal for scanning."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            response = requests.post(VT_SCAN_URL, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"VT Upload Error: {e}")
    return None

def get_scan_result(analysis_id):
    """Poll VirusTotal for scan result."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(10):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return data
            time.sleep(3)
        except:
            time.sleep(3)
    return None

def parse_vt_result(vt_data):
    """Parse VirusTotal result safely."""
    try:
        if not vt_data or "data" not in vt_data:
            return None
        
        attrs = vt_data["data"].get("attributes", {})
        
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            engines = attrs.get("last_analysis_results", {})
        elif "stats" in attrs:
            stats = attrs["stats"]
            engines = attrs.get("results", {})
        else:
            return None

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0) + stats.get("undetected", 0)
        total = malicious + suspicious + harmless

        detections = []
        for engine, result in engines.items():
            if result.get("category") in ("malicious", "suspicious"):
                detections.append({
                    "engine": engine,
                    "result": result.get("result", "detected"),
                    "category": result.get("category")
                })

        verdict = "clean"
        if malicious >= 3: verdict = "malicious"
        elif malicious >= 1 or suspicious >= 2: verdict = "suspicious"

        return {
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "detections": detections[:10]
        }
    except Exception as e:
        print(f"Parsing error: {e}")
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # 🛠️ WINDOWS FIX: Use a sanitized fixed filename for processing
    safe_filename = "scan_target.tmp"
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)

    try:
        # If the file already exists, remove it first to avoid permission errors
        if os.path.exists(filepath):
            os.remove(filepath)
        file.save(filepath)
    except Exception as e:
        return jsonify({"error": f"Failed to save file. Windows might be blocking it: {e}"}), 500

    # Compute hashes
    md5, sha1, sha256 = compute_hashes(filepath)
    if not sha256:
        return jsonify({"error": "Failed to read file for hashing."}), 500

    # Step 1: Check known hash
    vt_data = check_hash_virustotal(sha256)
    source = "hash_lookup"

    # Step 2: If not known, upload for fresh scan
    if vt_data is None:
        upload_result = upload_to_virustotal(filepath)
        if upload_result:
            analysis_id = upload_result["data"]["id"]
            vt_data = get_scan_result(analysis_id)
            source = "fresh_scan"

    # Cleanup temp file safely
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except:
        pass

    if vt_data is None:
        return jsonify({"error": "No results from Cloud API. Check API Key or Rate Limits."}), 500

    result = parse_vt_result(vt_data)
    if result is None:
         return jsonify({"error": "Failed to parse scan data."}), 500

    return jsonify({
        "filename": file.filename,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "source": source,
        "scan": result
    })

if __name__ == "__main__":
    app.run(debug=True)