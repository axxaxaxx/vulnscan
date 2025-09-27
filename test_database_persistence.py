#!/usr/bin/env python3
"""
Test database persistence issues
"""

import requests
import json
import time
from app import create_app, db
from app.models import Customer, Scan

def test_database_persistence():
    """Test if data persists in the database"""
    print("🧪 Testing database persistence...")
    
    app, celery = create_app()
    with app.app_context():
        try:
            # Test 1: Create customer via API
            print("\n1. Testing customer creation via API...")
            customer_data = {
                "name": "Test Customer API",
                "email": "testapi@example.com",
                "organization": "Test Org API"
            }
            
            response = requests.post('http://localhost:5000/api/customers', 
                                   json=customer_data,
                                   headers={'Content-Type': 'application/json'})
            
            if response.status_code == 201:
                customer = response.json()
                print(f"✅ Customer created via API: {customer['name']} (ID: {customer['id']})")
                customer_id = customer['id']
                
                # Test 2: Check if customer exists in database
                print("\n2. Checking database directly...")
                db_customer = Customer.query.get(customer_id)
                if db_customer:
                    print(f"✅ Customer found in database: {db_customer.name}")
                else:
                    print("❌ Customer NOT found in database")
                    return False
                
                # Test 3: Create scan via API
                print("\n3. Testing scan creation via API...")
                scan_data = {
                    "customer_id": customer_id,
                    "name": "Test Scan API",
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
                    print(f"✅ Scan created via API: {scan['name']} (ID: {scan['id']})")
                    scan_id = scan['id']
                    
                    # Test 4: Check if scan exists in database
                    print("\n4. Checking scan in database...")
                    db_scan = Scan.query.get(scan_id)
                    if db_scan:
                        print(f"✅ Scan found in database: {db_scan.name}")
                    else:
                        print("❌ Scan NOT found in database")
                        return False
                    
                    # Test 5: Fetch customers via API
                    print("\n5. Testing customer fetch via API...")
                    response = requests.get('http://localhost:5000/api/customers')
                    if response.status_code == 200:
                        customers = response.json()
                        test_customer = next((c for c in customers if c['id'] == customer_id), None)
                        if test_customer:
                            print(f"✅ Customer found in API response: {test_customer['name']}")
                        else:
                            print("❌ Customer NOT found in API response")
                            return False
                    else:
                        print(f"❌ Failed to fetch customers: {response.text}")
                        return False
                    
                    # Test 6: Fetch scans via API
                    print("\n6. Testing scan fetch via API...")
                    response = requests.get('http://localhost:5000/api/scans')
                    if response.status_code == 200:
                        scans = response.json()
                        test_scan = next((s for s in scans if s['id'] == scan_id), None)
                        if test_scan:
                            print(f"✅ Scan found in API response: {test_scan['name']}")
                        else:
                            print("❌ Scan NOT found in API response")
                            return False
                    else:
                        print(f"❌ Failed to fetch scans: {response.text}")
                        return False
                    
                    # Test 7: Check database session state
                    print("\n7. Checking database session state...")
                    print(f"   Session dirty: {db.session.dirty}")
                    print(f"   Session new: {db.session.new}")
                    print(f"   Session deleted: {db.session.deleted}")
                    
                    # Test 8: Force commit and check again
                    print("\n8. Testing forced commit...")
                    db.session.commit()
                    print("✅ Database session committed")
                    
                    # Re-check customer
                    db_customer = Customer.query.get(customer_id)
                    if db_customer:
                        print(f"✅ Customer still exists after commit: {db_customer.name}")
                    else:
                        print("❌ Customer disappeared after commit")
                        return False
                    
                    print("\n✅ All database persistence tests passed!")
                    return True
                    
                else:
                    print(f"❌ Scan creation failed: {response.text}")
                    return False
            else:
                print(f"❌ Customer creation failed: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
            return False
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            return False

def test_database_rollback():
    """Test database rollback behavior"""
    print("\n🧪 Testing database rollback...")
    
    app, celery = create_app()
    with app.app_context():
        try:
            # Create a customer that will cause an error
            customer = Customer(
                name="Test Rollback Customer",
                email="testrollback@example.com",
                organization="Test Rollback Org"
            )
            
            db.session.add(customer)
            db.session.flush()  # This will assign an ID
            
            print(f"✅ Customer added to session: {customer.name} (ID: {customer.id})")
            
            # Try to create another customer with the same email (should fail due to unique constraint)
            duplicate_customer = Customer(
                name="Duplicate Customer",
                email="testrollback@example.com",  # Same email
                organization="Duplicate Org"
            )
            
            db.session.add(duplicate_customer)
            
            try:
                db.session.commit()
                print("❌ Commit should have failed but didn't")
                return False
            except Exception as e:
                print(f"✅ Commit failed as expected: {e}")
                db.session.rollback()
                print("✅ Rollback successful")
                
                # Check if the first customer was rolled back
                db_customer = Customer.query.get(customer.id)
                if db_customer:
                    print("❌ Customer should have been rolled back but still exists")
                    return False
                else:
                    print("✅ Customer was properly rolled back")
                    return True
                    
        except Exception as e:
            print(f"❌ Rollback test failed: {e}")
            return False

def main():
    """Run all database tests"""
    print("=" * 60)
    print("🔧 DATABASE PERSISTENCE TEST")
    print("=" * 60)
    
    # Test 1: Basic persistence
    persistence_ok = test_database_persistence()
    
    # Test 2: Rollback behavior
    rollback_ok = test_database_rollback()
    
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS")
    print("=" * 60)
    print(f"Database Persistence: {'✅ PASS' if persistence_ok else '❌ FAIL'}")
    print(f"Database Rollback: {'✅ PASS' if rollback_ok else '❌ FAIL'}")
    
    if not persistence_ok:
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Check if database is properly initialized")
        print("2. Check if there are any database connection issues")
        print("3. Check if there are any transaction isolation issues")
        print("4. Check if there are any foreign key constraint issues")
        
    if not rollback_ok:
        print("\n🔧 ROLLBACK ISSUES:")
        print("1. Check if database supports transactions")
        print("2. Check if there are any session management issues")
        print("3. Check if there are any constraint violations")

if __name__ == '__main__':
    main()
