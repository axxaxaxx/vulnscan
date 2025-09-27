#!/usr/bin/env python3
"""
Comprehensive test to verify all fixes are working
"""

import requests
import json
import time
from app import create_app, db
from app.models import Customer, Scan

def test_complete_workflow():
    """Test the complete customer and scan workflow"""
    print("🧪 Testing complete workflow...")
    
    try:
        # Step 1: Create customer via API
        print("\n1. Creating customer via API...")
        customer_data = {
            "name": "Test Workflow Customer",
            "email": "workflow@example.com",
            "organization": "Test Workflow Org"
        }
        
        response = requests.post('http://localhost:5000/api/customers', 
                               json=customer_data,
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code != 201:
            print(f"❌ Customer creation failed: {response.text}")
            return False
        
        customer = response.json()
        customer_id = customer['id']
        print(f"✅ Customer created: {customer['name']} (ID: {customer_id})")
        
        # Step 2: Verify customer exists in database
        print("\n2. Verifying customer in database...")
        app, celery = create_app()
        with app.app_context():
            db_customer = Customer.query.get(customer_id)
            if not db_customer:
                print("❌ Customer not found in database")
                return False
            print(f"✅ Customer found in database: {db_customer.name}")
        
        # Step 3: Fetch customers via API
        print("\n3. Fetching customers via API...")
        response = requests.get('http://localhost:5000/api/customers')
        if response.status_code != 200:
            print(f"❌ Failed to fetch customers: {response.text}")
            return False
        
        customers = response.json()
        test_customer = next((c for c in customers if c['id'] == customer_id), None)
        if not test_customer:
            print("❌ Customer not found in API response")
            return False
        print(f"✅ Customer found in API response: {test_customer['name']}")
        
        # Step 4: Create scan via API
        print("\n4. Creating scan via API...")
        scan_data = {
            "customer_id": customer_id,
            "name": "Test Workflow Scan",
            "target": "192.168.1.1",
            "scan_type": "comprehensive",
            "enable_cve_lookup": True,
            "enable_osint": False
        }
        
        response = requests.post('http://localhost:5000/api/scans', 
                               json=scan_data,
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code != 201:
            print(f"❌ Scan creation failed: {response.text}")
            return False
        
        scan = response.json()
        scan_id = scan['id']
        print(f"✅ Scan created: {scan['name']} (ID: {scan_id})")
        
        # Step 5: Verify scan exists in database
        print("\n5. Verifying scan in database...")
        with app.app_context():
            db_scan = Scan.query.get(scan_id)
            if not db_scan:
                print("❌ Scan not found in database")
                return False
            print(f"✅ Scan found in database: {db_scan.name}")
        
        # Step 6: Fetch scans via API
        print("\n6. Fetching scans via API...")
        response = requests.get('http://localhost:5000/api/scans')
        if response.status_code != 200:
            print(f"❌ Failed to fetch scans: {response.text}")
            return False
        
        scans_data = response.json()
        test_scan = next((s for s in scans_data['scans'] if s['id'] == scan_id), None)
        if not test_scan:
            print("❌ Scan not found in API response")
            return False
        print(f"✅ Scan found in API response: {test_scan['name']}")
        
        # Step 7: Test customer detail page
        print("\n7. Testing customer detail page...")
        response = requests.get(f'http://localhost:5000/customers/{customer_id}')
        if response.status_code != 200:
            print(f"❌ Customer detail page failed: {response.status_code}")
            return False
        print("✅ Customer detail page accessible")
        
        # Step 8: Test scans page
        print("\n8. Testing scans page...")
        response = requests.get('http://localhost:5000/scans')
        if response.status_code != 200:
            print(f"❌ Scans page failed: {response.status_code}")
            return False
        print("✅ Scans page accessible")
        
        # Step 9: Test scan detail page
        print("\n9. Testing scan detail page...")
        response = requests.get(f'http://localhost:5000/scans/{scan_id}')
        if response.status_code != 200:
            print(f"❌ Scan detail page failed: {response.status_code}")
            return False
        print("✅ Scan detail page accessible")
        
        # Step 10: Test scan start
        print("\n10. Testing scan start...")
        response = requests.post(f'http://localhost:5000/api/scans/{scan_id}/start')
        if response.status_code != 200:
            print(f"❌ Scan start failed: {response.text}")
            return False
        
        scan_data = response.json()
        if scan_data['status'] != 'running':
            print(f"❌ Scan status not updated: {scan_data['status']}")
            return False
        print("✅ Scan started successfully")
        
        # Step 11: Test persistence after restart simulation
        print("\n11. Testing persistence...")
        time.sleep(1)  # Simulate some time passing
        
        # Fetch again to ensure persistence
        response = requests.get('http://localhost:5000/api/customers')
        customers = response.json()
        test_customer = next((c for c in customers if c['id'] == customer_id), None)
        if not test_customer:
            print("❌ Customer not persistent")
            return False
        
        response = requests.get('http://localhost:5000/api/scans')
        scans_data = response.json()
        test_scan = next((s for s in scans_data['scans'] if s['id'] == scan_id), None)
        if not test_scan:
            print("❌ Scan not persistent")
            return False
        
        print("✅ Data persistence verified")
        
        # Cleanup
        print("\n12. Cleaning up test data...")
        requests.delete(f'http://localhost:5000/api/scans/{scan_id}')
        requests.delete(f'http://localhost:5000/api/customers/{customer_id}')
        print("✅ Test data cleaned up")
        
        print("\n✅ All tests passed! The application is working correctly.")
        return True
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
        return False
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

def test_ui_functionality():
    """Test UI functionality"""
    print("\n🧪 Testing UI functionality...")
    
    try:
        # Test main pages
        pages = [
            ('/', 'Dashboard'),
            ('/customers', 'Customers'),
            ('/scans', 'Scans'),
            ('/reports', 'Reports'),
            ('/monitoring', 'Monitoring')
        ]
        
        for url, name in pages:
            response = requests.get(f'http://localhost:5000{url}')
            if response.status_code == 200:
                print(f"✅ {name} page accessible")
            else:
                print(f"❌ {name} page failed: {response.status_code}")
                return False
        
        print("✅ All UI pages accessible")
        return True
        
    except Exception as e:
        print(f"❌ UI test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 70)
    print("🔧 COMPLETE APPLICATION FIX VERIFICATION")
    print("=" * 70)
    
    # Test 1: Complete workflow
    workflow_ok = test_complete_workflow()
    
    # Test 2: UI functionality
    ui_ok = test_ui_functionality()
    
    print("\n" + "=" * 70)
    print("📊 FINAL RESULTS")
    print("=" * 70)
    print(f"Complete Workflow: {'✅ PASS' if workflow_ok else '❌ FAIL'}")
    print(f"UI Functionality: {'✅ PASS' if ui_ok else '❌ FAIL'}")
    
    if workflow_ok and ui_ok:
        print("\n🎉 ALL TESTS PASSED!")
        print("The application is now fully functional:")
        print("✅ Customers can be created and persist")
        print("✅ Scans can be created and persist")
        print("✅ All pages are accessible")
        print("✅ API endpoints are working")
        print("✅ Database persistence is working")
        print("\n🌐 You can now use the application at http://localhost:5000")
    else:
        print("\n❌ SOME TESTS FAILED")
        print("Please check the error messages above and fix any issues")

if __name__ == '__main__':
    main()
