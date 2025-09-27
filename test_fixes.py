#!/usr/bin/env python3
"""
Test script to verify the fixes work
"""

import requests
import json
import time

def test_scan_detail_and_port_config():
    """Test scan detail page and port configuration"""
    base_url = "http://localhost:5000"
    
    print("🧪 Testing scan detail page and port configuration...")
    
    try:
        # Test 1: Check if scan detail page loads
        print("1. Testing scan detail page...")
        response = requests.get(f"{base_url}/scans/1", timeout=5)
        if response.status_code == 200:
            print("   ✅ Scan detail page loads successfully")
        else:
            print(f"   ❌ Scan detail page failed: {response.status_code}")
    
    except requests.exceptions.ConnectionError:
        print("   ⚠️  Flask app not running, skipping test")
        return
    except Exception as e:
        print(f"   ❌ Error testing scan detail: {e}")
    
    try:
        # Test 2: Check if scans API works
        print("2. Testing scans API...")
        response = requests.get(f"{base_url}/api/scans", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Scans API works, found {data.get('total', 0)} scans")
        else:
            print(f"   ❌ Scans API failed: {response.status_code}")
    
    except Exception as e:
        print(f"   ❌ Error testing scans API: {e}")
    
    try:
        # Test 3: Test port configuration in scan creation
        print("3. Testing port configuration...")
        
        # First get customers
        customers_response = requests.get(f"{base_url}/api/customers", timeout=5)
        if customers_response.status_code == 200:
            customers = customers_response.json()
            if customers:
                customer_id = customers[0]['id']
                
                # Test scan creation with port configuration
                scan_data = {
                    "name": "Test Port Configuration",
                    "target": "127.0.0.1",
                    "customer_id": customer_id,
                    "scan_type": "comprehensive",
                    "port_range": "custom",
                    "custom_ports": "80,443,22",
                    "nmap_options": "-sS -O -A",
                    "enable_cve_lookup": True,
                    "enable_osint": False,
                    "enable_compliance_check": True
                }
                
                response = requests.post(
                    f"{base_url}/api/scans",
                    json=scan_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if response.status_code == 201:
                    scan = response.json()
                    print(f"   ✅ Scan created successfully with port config: {scan['id']}")
                    
                    # Test starting the scan
                    start_response = requests.post(f"{base_url}/api/scans/{scan['id']}/start", timeout=10)
                    if start_response.status_code == 200:
                        print("   ✅ Scan started successfully")
                    else:
                        print(f"   ❌ Scan start failed: {start_response.status_code}")
                else:
                    print(f"   ❌ Scan creation failed: {response.status_code}")
                    print(f"   Response: {response.text}")
            else:
                print("   ⚠️  No customers found, skipping scan creation test")
        else:
            print(f"   ❌ Failed to get customers: {customers_response.status_code}")
    
    except Exception as e:
        print(f"   ❌ Error testing port configuration: {e}")
    
    print("\n🎉 Test completed!")

if __name__ == '__main__':
    test_scan_detail_and_port_config()
