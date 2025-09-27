#!/usr/bin/env python3
"""
Simple test runner without advanced pytest features
"""

import os
import sys
import subprocess
from app import create_app, db

def run_simple_tests():
    """Run tests with basic pytest command"""
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
        
        # Run tests with basic pytest command
        print("\nRunning tests...")
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest', 
                'tests/', 
                '-v',
                '--tb=short',
                '--disable-warnings'
            ], capture_output=True, text=True, timeout=60)
            
            print("STDOUT:", result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            
            return result.returncode
            
        except subprocess.TimeoutExpired:
            print("❌ Tests timed out after 60 seconds")
            return 1
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            return 1

if __name__ == '__main__':
    result = run_simple_tests()
    sys.exit(result)
