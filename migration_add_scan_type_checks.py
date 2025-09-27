#!/usr/bin/env python3
"""
Migration script to add additional check columns to scan_types table
Run this script to update the database schema
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import ScanType

def run_migration():
    """Add new columns to scan_types table"""
    app, celery = create_app()
    
    with app.app_context():
        try:
            # Check if columns already exist
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('scan_types')]
            
            if 'enable_searchsploit' not in columns:
                print("Adding enable_searchsploit column...")
                db.engine.execute("ALTER TABLE scan_types ADD COLUMN enable_searchsploit BOOLEAN DEFAULT FALSE")
            
            if 'enable_osint' not in columns:
                print("Adding enable_osint column...")
                db.engine.execute("ALTER TABLE scan_types ADD COLUMN enable_osint BOOLEAN DEFAULT FALSE")
            
            if 'enable_cve_lookup' not in columns:
                print("Adding enable_cve_lookup column...")
                db.engine.execute("ALTER TABLE scan_types ADD COLUMN enable_cve_lookup BOOLEAN DEFAULT FALSE")
            
            if 'enable_compliance_check' not in columns:
                print("Adding enable_compliance_check column...")
                db.engine.execute("ALTER TABLE scan_types ADD COLUMN enable_compliance_check BOOLEAN DEFAULT FALSE")
            
            print("✅ Migration completed successfully!")
            
        except Exception as e:
            print(f"❌ Migration failed: {str(e)}")
            return False
    
    return True

if __name__ == "__main__":
    print("Running scan_types table migration...")
    success = run_migration()
    if success:
        print("Migration completed successfully!")
    else:
        print("Migration failed!")
        sys.exit(1)
