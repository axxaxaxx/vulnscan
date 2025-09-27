#!/usr/bin/env python3
"""
Test script to verify the vulnerability scanner installation
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        # Test basic imports
        import flask
        print("✓ Flask imported successfully")
        
        import sqlalchemy
        print("✓ SQLAlchemy imported successfully")
        
        import celery
        print("✓ Celery imported successfully")
        
        import redis
        print("✓ Redis imported successfully")
        
        import nmap
        print("✓ python-nmap imported successfully")
        
        import bs4
        print("✓ BeautifulSoup imported successfully")
        
        # Test app imports
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        from app import create_app, db
        print("✓ App package imported successfully")
        
        from app.models import Customer, Scan, Vulnerability
        print("✓ Database models imported successfully")
        
        # Test route imports
        from app.routes import main_bp, api_bp, scan_bp, report_bp, monitor_bp
        print("✓ Route blueprints imported successfully")
        
        # Test module imports
        from app.modules import NmapScanner, CVELookup, ComplianceChecker
        print("✓ Scanning modules imported successfully")
        
        # Test task imports
        from app.tasks import run_nmap_scan, run_cve_lookup
        print("✓ Celery tasks imported successfully")
        
        print("\n✅ All imports successful!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_app_creation():
    """Test if the Flask app can be created"""
    print("\nTesting Flask app creation...")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from app import create_app
        
        app, celery = create_app()
        print("✓ Flask app created successfully")
        print(f"✓ App name: {app.name}")
        print(f"✓ Celery app name: {celery.main}")
        
        return True
        
    except Exception as e:
        print(f"❌ App creation error: {e}")
        return False

def test_database_connection():
    """Test database connection"""
    print("\nTesting database connection...")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from app import create_app, db
        
        app, celery = create_app()
        
        with app.app_context():
            # Test database connection
            db.engine.execute('SELECT 1')
            print("✓ Database connection successful")
            
            # Test table creation
            db.create_all()
            print("✓ Database tables created successfully")
            
        return True
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("Vulnerability Scanner Installation Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_app_creation,
        test_database_connection
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 Installation test completed successfully!")
        print("You can now run the application with: python app.py")
    else:
        print("❌ Some tests failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
