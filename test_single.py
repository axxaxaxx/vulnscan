#!/usr/bin/env python3
"""
Test a single test to isolate issues
"""

import os
import sys
import pytest
from app import create_app, db

def test_single():
    """Run a single test"""
    # Add current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Create test app
    app, celery = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        print("✓ Database tables created")
        
        # Run just the NmapScanner test
        result = pytest.main([
            'tests/test_scan_modules.py::TestNmapScanner::test_scan_target_success',
            '-v',
            '--tb=short',
            '--disable-warnings'
        ])
        
        return result

if __name__ == '__main__':
    result = test_single()
    sys.exit(result)
