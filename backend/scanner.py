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

        # ===== STEP 2: POLL UNTIL SCAN IS ACTUALLY COMPLETE =====
        # VirusTotal analysis is async. We poll until status == "completed".
        # We ALSO require the stats to be non-empty (total > 0), because VT's
        # own backend can briefly report status "completed" a moment before
        # the detection stats are fully written/visible (eventual consistency
        # on their end). Trusting status alone caused intermittent false
        # "0 malicious" results on files that are definitely malicious.
        max_wait = 90           # total seconds to wait before giving up
        poll_interval = 5       # seconds between checks
        elapsed = 0
        data = None
        stats = {}

        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval

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

            data = result_response.json()
            status = data['data']['attributes'].get('status')
            stats = data['data']['attributes'].get('stats', {})
            stats_total = sum(stats.values()) if stats else 0

            if status == 'completed' and stats_total > 0:
                break
        else:
            # Loop finished without a `break` -> never got a real completed
            # result with populated stats.
            return {
                'error': 'Scan is taking longer than expected. Please try scanning again.',
                'file_name': file_name,
                'file_size': file_size,
                'file_type': file_type,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'analysis_id': analysis_id
            }

        # ===== STEP 3: EXTRACT RESULTS =====
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