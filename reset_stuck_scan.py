#!/usr/bin/env python3
"""
Reset stuck scan script
"""

import requests
import json

def reset_stuck_scan():
    """Reset the stuck scan via API"""
    try:
        print("🔧 Resetting stuck scan...")
        
        response = requests.post('http://localhost:5000/api/scans/reset-stuck')
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ {result['message']}")
            print(f"   Reset {result['reset_count']} scans")
        else:
            print(f"❌ Failed to reset stuck scans: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    reset_stuck_scan()
