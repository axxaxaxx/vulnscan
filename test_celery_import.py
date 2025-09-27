#!/usr/bin/env python3
"""
Test script to verify Celery imports work correctly
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_celery_imports():
    """Test that all Celery-related imports work"""
    try:
        print("Testing Celery imports...")
        
        # Test app imports
        from app import create_app, db, celery
        print("✓ App package imported successfully")
        print(f"✓ Celery instance: {celery}")
        
        # Test tasks imports
        from app.tasks import celery as tasks_celery
        print("✓ Tasks celery imported successfully")
        print(f"✓ Tasks celery instance: {tasks_celery}")
        
        # Test that they're the same instance
        if celery is tasks_celery:
            print("✓ Celery instances are the same")
        else:
            print("⚠ Celery instances are different")
        
        # Test route imports
        from app.routes.scan import scan_bp
        print("✓ Scan route imported successfully")
        
        # Test task function imports
        from app.tasks import run_nmap_scan, run_cve_lookup
        print("✓ Task functions imported successfully")
        
        print("\n✅ All Celery imports successful!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    success = test_celery_imports()
    sys.exit(0 if success else 1)
