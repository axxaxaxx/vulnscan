#!/usr/bin/env python3
"""
Flask CLI entry point for the vulnerability scanner application
This file is used by Flask CLI commands like 'flask db init', 'flask db migrate', etc.
"""

import os
import sys
from dotenv import load_dotenv

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

# Import the Flask app
from app import create_app, db

# Create app instance for Flask CLI
app, celery = create_app()

# Make app available for Flask CLI
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
