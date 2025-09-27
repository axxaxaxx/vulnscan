"""
Vulnerability Scanner Web Application
Main Flask application entry point
"""

import os
import sys
from dotenv import load_dotenv

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

# Import from the app package
from app import create_app, db

# Create app instance
app, celery = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Initialize default scan types
        try:
            from app.modules.scan_type_initializer import ensure_default_scan_types
            ensure_default_scan_types()
            print("✅ Default scan types initialized successfully!")
        except Exception as e:
            print(f"Warning: Could not initialize default scan types: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
