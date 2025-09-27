#!/usr/bin/env python3
"""
Start Celery worker for processing scan tasks
"""

import os
import sys
import subprocess

def start_celery_worker():
    """Start the Celery worker"""
    print("🚀 Starting Celery worker...")
    
    # Change to the project directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        # Start Celery worker
        cmd = [
            sys.executable, '-m', 'celery',
            '-A', 'app.tasks.scan_tasks',
            'worker',
            '--loglevel=info',
            '--concurrency=2'
        ]
        
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        
    except KeyboardInterrupt:
        print("\n⏹️  Celery worker stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start Celery worker: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    start_celery_worker()
