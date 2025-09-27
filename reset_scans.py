#!/usr/bin/env python3
"""
Reset stuck scans directly in database
"""

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def reset_stuck_scans():
    """Reset stuck scans directly in the database"""
    try:
        print("🔧 Resetting stuck scans...")
        
        # Import the application
        from app import create_app, db
        from app.models import Scan
        
        # Create app context
        app, celery = create_app()
        
        with app.app_context():
            # Find all running scans
            running_scans = Scan.query.filter_by(status='running').all()
            
            if not running_scans:
                print("✅ No running scans found")
                return
            
            print(f"Found {len(running_scans)} running scans:")
            
            for scan in running_scans:
                print(f"  - Scan {scan.id}: {scan.name}")
                
                # Mark as failed
                scan.status = 'failed'
                scan.completed_at = datetime.utcnow()
                scan.progress = 0
                
            # Commit changes
            db.session.commit()
            
            print(f"✅ Reset {len(running_scans)} stuck scans")
            print("All scans have been marked as 'failed' and can be restarted")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    reset_stuck_scans()
