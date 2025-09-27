#!/usr/bin/env python3
"""
Fix pending scans by starting required services and processing tasks
"""

import os
import sys
import time
import subprocess
from app import create_app, db
from app.models import Scan, ScanTask
from app.tasks.scan_tasks import celery

def check_and_start_redis():
    """Check if Redis is running and start it if needed"""
    print("🔍 Checking Redis...")
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        result = r.ping()
        if result:
            print("✅ Redis is running")
            return True
    except:
        pass
    
    print("❌ Redis is not running. Attempting to start...")
    try:
        # Try to start Redis
        subprocess.Popen(['redis-server'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # Wait for Redis to start
        
        # Check again
        r = redis.Redis(host='localhost', port=6379, db=0)
        result = r.ping()
        if result:
            print("✅ Redis started successfully")
            return True
    except Exception as e:
        print(f"❌ Failed to start Redis: {e}")
        print("Please start Redis manually: redis-server")
        return False

def check_celery_worker():
    """Check if Celery worker is running"""
    print("\n🔍 Checking Celery worker...")
    try:
        inspect = celery.control.inspect()
        active_workers = inspect.active()
        
        if active_workers:
            print(f"✅ Celery worker is running: {list(active_workers.keys())}")
            return True
        else:
            print("❌ No Celery worker found")
            return False
    except Exception as e:
        print(f"❌ Celery worker check failed: {e}")
        return False

def start_celery_worker():
    """Start Celery worker in background"""
    print("\n🚀 Starting Celery worker...")
    try:
        # Start worker in background
        cmd = [
            sys.executable, '-m', 'celery',
            '-A', 'app.tasks.scan_tasks',
            'worker',
            '--loglevel=info',
            '--concurrency=2',
            '--detach'
        ]
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)  # Wait for worker to start
        
        # Check if worker is now running
        if check_celery_worker():
            print("✅ Celery worker started successfully")
            return True
        else:
            print("❌ Failed to start Celery worker")
            return False
            
    except Exception as e:
        print(f"❌ Error starting Celery worker: {e}")
        return False

def process_pending_scans():
    """Process any pending scans"""
    print("\n🔍 Checking for pending scans...")
    
    app, celery_app = create_app()
    with app.app_context():
        # Find pending scans
        pending_scans = Scan.query.filter_by(status='pending').all()
        running_scans = Scan.query.filter_by(status='running').all()
        
        print(f"📊 Pending scans: {len(pending_scans)}")
        print(f"📊 Running scans: {len(running_scans)}")
        
        if pending_scans:
            print("\n🔄 Processing pending scans...")
            for scan in pending_scans:
                print(f"   - Scan {scan.id}: {scan.name} ({scan.target})")
                
                # Update status to running
                scan.status = 'running'
                scan.started_at = db.func.now()
                db.session.commit()
                
                # Start tasks
                try:
                    # Start nmap scan
                    nmap_task = celery.tasks['app.tasks.scan_tasks.run_nmap_scan'].delay(scan.id)
                    print(f"     ✅ Started nmap task: {nmap_task.id}")
                    
                    # Create task record
                    task_record = ScanTask(
                        task_id=nmap_task.id,
                        scan_id=scan.id,
                        task_type='nmap_scan',
                        status='pending'
                    )
                    db.session.add(task_record)
                    db.session.commit()
                    
                except Exception as e:
                    print(f"     ❌ Failed to start tasks for scan {scan.id}: {e}")
                    scan.status = 'failed'
                    db.session.commit()

def main():
    """Main function to fix pending scans"""
    print("=" * 60)
    print("🔧 PENDING SCANS FIX TOOL")
    print("=" * 60)
    
    # Step 1: Check and start Redis
    if not check_and_start_redis():
        print("\n❌ Cannot proceed without Redis. Please start Redis manually.")
        return
    
    # Step 2: Check and start Celery worker
    if not check_celery_worker():
        if not start_celery_worker():
            print("\n❌ Cannot proceed without Celery worker.")
            print("Please start manually: celery -A app.tasks.scan_tasks worker --loglevel=info")
            return
    
    # Step 3: Process pending scans
    process_pending_scans()
    
    print("\n" + "=" * 60)
    print("✅ PENDING SCANS FIX COMPLETED")
    print("=" * 60)
    print("\nTo keep the system running:")
    print("1. Keep Redis running: redis-server")
    print("2. Keep Celery worker running: celery -A app.tasks.scan_tasks worker --loglevel=info")
    print("3. Or use the start_worker.py script: python start_worker.py")

if __name__ == '__main__':
    main()
