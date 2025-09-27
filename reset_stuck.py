# -*- coding: utf-8 -*-
"""
Reset stuck scans
"""

from app import create_app, db
from app.models import Scan
from datetime import datetime

def main():
    app, celery = create_app()
    with app.app_context():
        running_scans = Scan.query.filter_by(status='running').all()
        print(f"Found {len(running_scans)} running scans")
        
        for scan in running_scans:
            scan.status = 'failed'
            scan.completed_at = datetime.utcnow()
            print(f"Reset scan {scan.id}: {scan.name}")
        
        db.session.commit()
        print(f"Reset {len(running_scans)} stuck scans")

if __name__ == '__main__':
    main()
