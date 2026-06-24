import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()

API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
BASE_URL = 'https://www.virustotal.com/api/v3'

def scan_file(file_path, file_name, file_size, file_type):
    headers = {
        'x-apikey': API_KEY
    }

    try:
        # ===== STEP 1: UPLOAD FILE TO VIRUSTOTAL =====
        with open(file_path, 'rb') as f:
            files = {'file': (file_name, f)}
            upload_response = requests.post(
                f'{BASE_URL}/files',
                headers=headers,
                files=files
            )

        if upload_response.status_code != 200:
            return {
                'error': 'Failed to upload file to VirusTotal',
                'file_name': file_name,
                'file_size': file_size,
                'file_type': file_type,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0
            }

        # Get analysis ID
        analysis_id = upload_response.json()['data']['id']

        # ===== STEP 2: WAIT FOR SCAN TO COMPLETE =====
        time.sleep(15)

        # ===== STEP 3: GET RESULTS =====
        result_response = requests.get(
            f'{BASE_URL}/analyses/{analysis_id}',
            headers=headers
        )

        if result_response.status_code != 200:
            return {
                'error': 'Failed to get scan results',
                'file_name': file_name,
                'file_size': file_size,
                'file_type': file_type,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0
            }

        # ===== STEP 4: EXTRACT RESULTS =====
        data = result_response.json()
        stats = data['data']['attributes']['stats']

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        clean = undetected + harmless

        return {
            'file_name': file_name,
            'file_size': file_size,
            'file_type': file_type,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'analysis_id': analysis_id
        }

    except Exception as e:
        return {
            'error': str(e),
            'file_name': file_name,
            'file_size': file_size,
            'file_type': file_type,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0
        }