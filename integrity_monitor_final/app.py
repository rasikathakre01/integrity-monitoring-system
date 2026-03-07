from flask import Flask, render_template, request, jsonify
import hashlib
import os
import json
import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'integrity_monitor_secret_2024'

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
HASH_STORE = os.path.join(os.path.dirname(__file__), 'hash_store.json')
LOG_FILE = os.path.join(os.path.dirname(__file__), 'audit_log.json')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def load_hash_store():
    if os.path.exists(HASH_STORE):
        with open(HASH_STORE, 'r') as f:
            return json.load(f)
    return {}


def save_hash_store(store):
    with open(HASH_STORE, 'w') as f:
        json.dump(store, f, indent=2)


def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            return json.load(f)
    return []


def save_log(entry):
    logs = load_logs()
    logs.insert(0, entry)
    logs = logs[:100]
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)


def compute_hashes(data):
    return {
        'md5':    hashlib.md5(data).hexdigest(),
        'sha1':   hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
    }


def get_stats():
    store = load_hash_store()
    logs = load_logs()
    tampered_count = sum(1 for l in logs if l.get('status') == 'TAMPERED')
    verified_count = sum(1 for l in logs if l.get('status') == 'INTACT')
    return {
        'total_files': len(store),
        'tampered':    tampered_count,
        'verified':    verified_count,
        'total_checks': len([l for l in logs if l.get('action') == 'VERIFY'])
    }


# ─── ROUTES ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    stats = get_stats()
    logs = load_logs()[:5]
    return render_template('index.html', stats=stats, recent_logs=logs)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})

    filename = secure_filename(file.filename)
    data = file.read()
    hashes = compute_hashes(data)
    file_size = len(data)

    store = load_hash_store()
    timestamp = datetime.datetime.now().isoformat()
    already_existed = filename in store

    store[filename] = {
        'hashes':        hashes,
        'size':          file_size,
        'uploaded_at':   timestamp,
        'original_name': file.filename,
    }
    save_hash_store(store)

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(filepath, 'wb') as f:
        f.write(data)

    save_log({
        'action':    'UPLOAD' if not already_existed else 'RE-UPLOAD',
        'filename':  filename,
        'sha256':    hashes['sha256'],
        'size':      file_size,
        'timestamp': timestamp,
        'status':    'SUCCESS'
    })

    return jsonify({
        'success':   True,
        'filename':  filename,
        'size':      file_size,
        'hashes':    hashes,
        'timestamp': timestamp,
        'message':   'File registered successfully'
    })


@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})

    filename = secure_filename(file.filename)
    data = file.read()
    current_hashes = compute_hashes(data)
    timestamp = datetime.datetime.now().isoformat()
    store = load_hash_store()

    if filename not in store:
        save_log({
            'action':    'VERIFY',
            'filename':  filename,
            'sha256':    current_hashes['sha256'],
            'size':      len(data),
            'timestamp': timestamp,
            'status':    'NOT_FOUND'
        })
        return jsonify({
            'success':        True,
            'status':         'not_found',
            'filename':       filename,
            'current_hashes': current_hashes,
            'message':        'File not found in registry'
        })

    original = store[filename]
    original_hashes = original['hashes']

    hash_comparison = {}
    tampered = False
    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
        match = current_hashes[algo] == original_hashes[algo]
        hash_comparison[algo] = {
            'original': original_hashes[algo],
            'current':  current_hashes[algo],
            'match':    match
        }
        if not match:
            tampered = True

    size_match = len(data) == original['size']
    status = 'tampered' if tampered or not size_match else 'intact'

    save_log({
        'action':    'VERIFY',
        'filename':  filename,
        'sha256':    current_hashes['sha256'],
        'size':      len(data),
        'timestamp': timestamp,
        'status':    'TAMPERED' if status == 'tampered' else 'INTACT'
    })

    return jsonify({
        'success':          True,
        'status':           status,
        'filename':         filename,
        'hash_comparison':  hash_comparison,
        'size_match':       size_match,
        'original_size':    original['size'],
        'current_size':     len(data),
        'registered_at':    original['uploaded_at'],
        'verified_at':      timestamp,
        'message':          '⚠️ TAMPERING DETECTED!' if status == 'tampered' else '✅ File integrity verified!'
    })


@app.route('/registry')
def registry():
    return jsonify({'files': load_hash_store()})


@app.route('/logs')
def get_logs():
    return jsonify({'logs': load_logs()})


@app.route('/stats')
def stats():
    return jsonify(get_stats())


@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    store = load_hash_store()
    filename = secure_filename(filename)
    if filename in store:
        del store[filename]
        save_hash_store(store)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        save_log({
            'action':    'DELETE',
            'filename':  filename,
            'timestamp': datetime.datetime.now().isoformat(),
            'status':    'REMOVED'
        })
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'File not found'})


if __name__ == '__main__':
    print("=" * 55)
    print("  🛡  Integrity Monitoring System")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True, port=5000)
