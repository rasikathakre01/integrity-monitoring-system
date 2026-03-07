<<<<<<< HEAD
# integrity-monitoring-system
This project is a File Integrity Monitoring System built using Flask. It allows users to upload files, generate hash values, and verify file integrity to detect any tampering or unauthorized changes.
Technologies Used:
Python
Flask
HTML, CSS, JavaScript
JSON
=======
# 🛡 Integrity Monitoring System

A cryptographic file integrity monitoring web app built with Python & Flask.

## Features
- Upload & register files with MD5, SHA-1, SHA-256, SHA-512 hashes
- Verify file integrity — detect any tampering
- Live file registry with delete support
- Full audit log
- Drag & drop interface

## Setup & Run

```bash
pip install -r requirements.txt
python app.py
```

Then open: http://127.0.0.1:5000

## Project Structure

```
integrity_monitor/
├── app.py                  # Flask backend
├── requirements.txt        # Dependencies
├── hash_store.json         # Auto-created at runtime
├── audit_log.json          # Auto-created at runtime
├── static/
│   └── uploads/            # Uploaded files stored here
└── templates/
    └── index.html          # Frontend UI
```

## Authors
- Rasika Thakre (CS23183)
- Sayali Padole (CS23154)
>>>>>>> 96782b3 (Initial commit)
