#!/usr/bin/env python3
"""
Comprehensive test runner for the vulnerability scanner application
Handles SQLAlchemy session management and other test issues
"""

import os
import sys
import pytest
from app import create_app, db

def setup_test_environment():
    """Set up the test environment"""
    # Add current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Create test app
    app, celery = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    return app

def run_tests():
    """Run all tests with proper setup"""
    print("Setting up test environment...")
    app = setup_test_environment()
    
    with app.app_context():
        db.create_all()
        print("✓ Database tables created")
        
        # Run tests with memory optimization
        print("\nRunning tests...")
        result = pytest.main([
            'tests/',
            '-v',
            '--tb=short',
            '--disable-warnings',
            '--maxfail=3'
        ])
        
        return result

if __name__ == '__main__':
    result = run_tests()
    sys.exit(result)
