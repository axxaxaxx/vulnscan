#!/usr/bin/env python3
"""
Test script to verify modal fixes are working
"""

import requests
import json
import time

def test_customer_creation():
    """Test customer creation via API"""
    print("🧪 Testing customer creation...")
    
    # Test data
    customer_data = {
        "name": "Test Customer",
        "email": "test@example.com",
        "organization": "Test Org"
    }
    
    try:
        # Create customer
        response = requests.post('http://localhost:5000/api/customers', 
                               json=customer_data,
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code == 201:
            customer = response.json()
            print(f"✅ Customer created successfully: {customer['name']} (ID: {customer['id']})")
            
            # Test fetching customers
            response = requests.get('http://localhost:5000/api/customers')
            if response.status_code == 200:
                customers = response.json()
                print(f"✅ Customers list retrieved: {len(customers)} customers found")
                
                # Check if our test customer is in the list
                test_customer = next((c for c in customers if c['email'] == 'test@example.com'), None)
                if test_customer:
                    print(f"✅ Test customer found in list: {test_customer['name']}")
                    
                    # Test updating customer
                    update_data = {
                        "name": "Updated Test Customer",
                        "email": "updated@example.com",
                        "organization": "Updated Test Org"
                    }
                    
                    response = requests.put(f'http://localhost:5000/api/customers/{test_customer["id"]}',
                                          json=update_data,
                                          headers={'Content-Type': 'application/json'})
                    
                    if response.status_code == 200:
                        print("✅ Customer updated successfully")
                        
                        # Test deleting customer
                        response = requests.delete(f'http://localhost:5000/api/customers/{test_customer["id"]}')
                        if response.status_code == 200:
                            print("✅ Customer deleted successfully")
                        else:
                            print(f"❌ Customer deletion failed: {response.text}")
                    else:
                        print(f"❌ Customer update failed: {response.text}")
                else:
                    print("❌ Test customer not found in list")
            else:
                print(f"❌ Failed to fetch customers: {response.text}")
        else:
            print(f"❌ Customer creation failed: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")

def test_scan_creation():
    """Test scan creation via API"""
    print("\n🧪 Testing scan creation...")
    
    # First create a customer for the scan
    customer_data = {
        "name": "Scan Test Customer",
        "email": "scantest@example.com",
        "organization": "Scan Test Org"
    }
    
    try:
        # Create customer
        response = requests.post('http://localhost:5000/api/customers', 
                               json=customer_data,
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code == 201:
            customer = response.json()
            print(f"✅ Test customer created: {customer['name']} (ID: {customer['id']})")
            
            # Create scan
            scan_data = {
                "customer_id": customer['id'],
                "name": "Test Scan",
                "target": "192.168.1.1",
                "scan_type": "comprehensive",
                "enable_cve_lookup": True,
                "enable_osint": False
            }
            
            response = requests.post('http://localhost:5000/api/scans', 
                                   json=scan_data,
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 201:
                scan = response.json()
                print(f"✅ Scan created successfully: {scan['name']} (ID: {scan['id']})")
                print(f"   Status: {scan['status']}")
                print(f"   Target: {scan['target']}")
                
                # Test fetching scans
                response = requests.get('http://localhost:5000/api/scans')
                if response.status_code == 200:
                    scans = response.json()
                    print(f"✅ Scans list retrieved: {len(scans)} scans found")
                else:
                    print(f"❌ Failed to fetch scans: {response.text}")
            else:
                print(f"❌ Scan creation failed: {response.text}")
        else:
            print(f"❌ Customer creation failed: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")

def main():
    """Run all tests"""
    print("=" * 60)
    print("🔧 MODAL FIXES VERIFICATION TEST")
    print("=" * 60)
    
    print("\n📋 Testing API endpoints...")
    test_customer_creation()
    test_scan_creation()
    
    print("\n" + "=" * 60)
    print("✅ API TESTS COMPLETED")
    print("=" * 60)
    print("\n🌐 To test the UI fixes:")
    print("1. Open http://localhost:5000/customers")
    print("2. Click 'New Customer' button")
    print("3. Fill out the form and click 'Save Customer'")
    print("4. Verify:")
    print("   - Modal closes automatically")
    print("   - Success notification appears")
    print("   - New customer appears in the table")
    print("   - No page reload occurs")
    print("\n5. Test editing:")
    print("   - Click 'Edit' on a customer")
    print("   - Modify details and save")
    print("   - Verify modal closes and table updates")
    print("\n6. Test keyboard support:")
    print("   - Press ESC to close modal")
    print("   - Click outside modal to close")

if __name__ == '__main__':
    main()
