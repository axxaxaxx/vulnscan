#!/usr/bin/env python3
"""
Diagnostic script to check Celery and Redis status
"""

import os
import sys
import time
from app import create_app, db
from app.tasks.scan_tasks import celery
import redis

def check_redis():
    """Check if Redis is running and accessible"""
    print("🔍 Checking Redis connection...")
    try:
        r = redis.Redis(host='localhost', port=6379, db=0)
        result = r.ping()
        if result:
            print("✅ Redis is running and accessible")
            return True
        else:
            print("❌ Redis ping failed")
            return False
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return False

def check_celery_worker():
    """Check if Celery worker is running"""
    print("\n🔍 Checking Celery worker status...")
    try:
        # Get active workers
        inspect = celery.control.inspect()
        active_workers = inspect.active()
        
        if active_workers:
            print(f"✅ Celery workers are active: {list(active_workers.keys())}")
            return True
        else:
            print("❌ No active Celery workers found")
            return False
    except Exception as e:
        print(f"❌ Celery worker check failed: {e}")
        return False

def test_celery_task():
    """Test if Celery can process a simple task"""
    print("\n🔍 Testing Celery task execution...")
    try:
        # Create a simple test task
        @celery.task
        def test_task():
            return "Test task completed"
        
        # Submit the task
        result = test_task.delay()
        print(f"✅ Task submitted with ID: {result.id}")
        
        # Wait for result (with timeout)
        try:
            task_result = result.get(timeout=10)
            print(f"✅ Task completed successfully: {task_result}")
            return True
        except Exception as e:
            print(f"❌ Task execution failed: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Task submission failed: {e}")
        return False

def check_pending_tasks():
    """Check for pending tasks in the queue"""
    print("\n🔍 Checking for pending tasks...")
    try:
        inspect = celery.control.inspect()
        scheduled = inspect.scheduled()
        active = inspect.active()
        reserved = inspect.reserved()
        
        total_pending = 0
        if scheduled:
            total_pending += sum(len(tasks) for tasks in scheduled.values())
        if reserved:
            total_pending += sum(len(tasks) for tasks in reserved.values())
            
        print(f"📊 Scheduled tasks: {scheduled}")
        print(f"📊 Active tasks: {active}")
        print(f"📊 Reserved tasks: {reserved}")
        print(f"📊 Total pending tasks: {total_pending}")
        
        return total_pending
    except Exception as e:
        print(f"❌ Failed to check pending tasks: {e}")
        return -1

def main():
    """Run all diagnostic checks"""
    print("=" * 50)
    print("Celery and Redis Diagnostic Tool")
    print("=" * 50)
    
    # Create app context
    app, celery_app = create_app()
    
    with app.app_context():
        # Check Redis
        redis_ok = check_redis()
        
        # Check Celery worker
        worker_ok = check_celery_worker()
        
        # Check pending tasks
        pending_count = check_pending_tasks()
        
        # Test task execution
        task_ok = test_celery_task()
        
        print("\n" + "=" * 50)
        print("DIAGNOSTIC SUMMARY")
        print("=" * 50)
        print(f"Redis Status: {'✅ OK' if redis_ok else '❌ FAILED'}")
        print(f"Celery Worker: {'✅ OK' if worker_ok else '❌ FAILED'}")
        print(f"Task Execution: {'✅ OK' if task_ok else '❌ FAILED'}")
        print(f"Pending Tasks: {pending_count}")
        
        if not redis_ok:
            print("\n🔧 SOLUTION: Start Redis server")
            print("   On Linux/macOS: redis-server")
            print("   On Windows: redis-server.exe")
            print("   Or: sudo systemctl start redis")
            
        if not worker_ok:
            print("\n🔧 SOLUTION: Start Celery worker")
            print("   celery -A app.tasks.scan_tasks worker --loglevel=info")
            
        if not task_ok and redis_ok and worker_ok:
            print("\n🔧 SOLUTION: Check task configuration and imports")
            
        if pending_count > 0:
            print(f"\n⚠️  WARNING: {pending_count} tasks are pending")
            print("   This might indicate worker issues or task failures")

if __name__ == '__main__':
    main()
