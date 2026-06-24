from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
from scanner import scan_file

app = Flask(__name__)
CORS(app)  # Allow frontend to talk to backend

# ===== HOME ROUTE =====
@app.route('/')
def home():
    return jsonify({'message': 'Scannova Backend is Running! 🛡️'})

# ===== SCAN ROUTE =====
@app.route('/scan', methods=['POST'])
def scan():
    # Check if file is in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    # Check if file is empty
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Get file details
        file_name = file.filename
        file_content = file.read()
        file_size = len(file_content)

        # Convert file size to readable format
        if file_size < 1024:
            file_size_str = f'{file_size} B'
        elif file_size < 1024 * 1024:
            file_size_str = f'{file_size // 1024} KB'
        else:
            file_size_str = f'{file_size // (1024 * 1024)} MB'

        # Get file extension as type
        file_ext = os.path.splitext(file_name)[1].upper()
        file_type = file_ext if file_ext else 'Unknown'

        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
            temp_file.write(file_content)
            temp_path = temp_file.name

        # Scan the file
        result = scan_file(
            file_path=temp_path,
            file_name=file_name,
            file_size=file_size_str,
            file_type=file_type
        )

        # Delete temp file after scanning
        os.unlink(temp_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== RUN APP =====
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)