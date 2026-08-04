# 🛡️ IoT Shield — File Threat Scanner
### Mini Project: IoT & Cloud Security

A web-based antivirus tool that scans uploaded files using the **VirusTotal Cloud API**.
Computes file hashes (MD5, SHA1, SHA256) and checks them against 70+ antivirus engines.

---

## 📁 Project Structure
```
antivirus/
├── app.py              ← Flask backend (API + hash logic)
├── requirements.txt    ← Python dependencies
├── templates/
│   └── index.html      ← Frontend UI
└── uploads/            ← Temp folder (auto-created)
```

---

## ⚙️ Setup Instructions

### 1. Get a FREE VirusTotal API Key
- Go to: https://www.virustotal.com
- Register a free account
- Go to your profile → API Key
- Copy the key

### 2. Add your API Key
Open `app.py` and replace:
```python
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
```
with your actual key.

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
python app.py
```

### 5. Open in browser
```
http://localhost:5000
```

---

## 🔍 How It Works

1. User uploads a file via the web UI
2. Backend computes **MD5, SHA1, SHA256** hashes
3. Queries VirusTotal to check if the hash is **already known**
4. If unknown → uploads file for a **fresh scan**
5. Results shown: verdict (clean/suspicious/malicious), engine detections, hashes

---

## 🎯 Subject Relevance: IoT + Cloud Security

| Concept | How It's Used |
|---|---|
| Cloud API | VirusTotal cloud-based threat intelligence |
| File Hashing | MD5/SHA1/SHA256 integrity checking |
| IoT Relevance | Firmware/file scanning before IoT OTA updates |
| Security | Malware detection, threat classification |
| Web Interface | Real-time scan results dashboard |

---

## 🚀 Demo Flow
1. Run the Flask server
2. Open browser at localhost:5000
3. Upload a safe file (e.g., a .txt) → shows ✅ Clean
4. Upload EICAR test file → shows ❌ Malicious (safe test virus)

> 💡 Download EICAR test file from: https://www.eicar.org/download-anti-malware-testfile/
