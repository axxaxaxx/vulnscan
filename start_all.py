#!/usr/bin/env python3
"""
Start all services for the vulnerability scanner application
"""

import os
import sys
import time
import subprocess
import signal
import threading
from app import create_app, db

class ServiceManager:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def start_redis(self):
        """Start Redis server"""
        print("🔴 Starting Redis server...")
        try:
            # Check if Redis is already running
            import redis
            r = redis.Redis(host='localhost', port=6379, db=0)
            if r.ping():
                print("✅ Redis is already running")
                return True
        except:
            pass
        
        try:
            # Start Redis
            proc = subprocess.Popen(['redis-server'], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL)
            self.processes.append(('Redis', proc))
            time.sleep(2)
            
            # Verify Redis started
            r = redis.Redis(host='localhost', port=6379, db=0)
            if r.ping():
                print("✅ Redis started successfully")
                return True
            else:
                print("❌ Redis failed to start")
                return False
        except Exception as e:
            print(f"❌ Failed to start Redis: {e}")
            return False
    
    def start_celery_worker(self):
        """Start Celery worker"""
        print("🔄 Starting Celery worker...")
        try:
            cmd = [
                sys.executable, '-m', 'celery',
                '-A', 'app.tasks.scan_tasks',
                'worker',
                '--loglevel=info',
                '--concurrency=2'
            ]
            
            proc = subprocess.Popen(cmd, 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE,
                                  text=True)
            self.processes.append(('Celery Worker', proc))
            
            # Start a thread to monitor Celery output
            def monitor_celery():
                for line in proc.stdout:
                    if self.running:
                        print(f"[CELERY] {line.strip()}")
            
            celery_thread = threading.Thread(target=monitor_celery, daemon=True)
            celery_thread.start()
            
            time.sleep(3)  # Wait for worker to initialize
            print("✅ Celery worker started successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start Celery worker: {e}")
            return False
    
    def start_flask_app(self):
        """Start Flask application"""
        print("🌐 Starting Flask application...")
        try:
            app, celery = create_app()
            
            # Create database tables
            with app.app_context():
                db.create_all()
                print("✅ Database tables created")
            
            # Start Flask app
            app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
            
        except Exception as e:
            print(f"❌ Failed to start Flask app: {e}")
            return False
    
    def cleanup(self):
        """Clean up all processes"""
        print("\n🛑 Shutting down services...")
        self.running = False
        
        for name, proc in self.processes:
            try:
                print(f"   Stopping {name}...")
                proc.terminate()
                proc.wait(timeout=5)
                print(f"   ✅ {name} stopped")
            except subprocess.TimeoutExpired:
                print(f"   ⚠️  {name} didn't stop gracefully, forcing...")
                proc.kill()
            except Exception as e:
                print(f"   ❌ Error stopping {name}: {e}")
    
    def run(self):
        """Run all services"""
        print("=" * 60)
        print("🚀 VULNERABILITY SCANNER STARTUP")
        print("=" * 60)
        
        # Set up signal handlers
        def signal_handler(sig, frame):
            print(f"\nReceived signal {sig}")
            self.cleanup()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            # Start Redis
            if not self.start_redis():
                print("❌ Cannot start without Redis")
                return False
            
            # Start Celery worker
            if not self.start_celery_worker():
                print("❌ Cannot start without Celery worker")
                return False
            
            print("\n✅ All services started successfully!")
            print("🌐 Application will be available at: http://localhost:5000")
            print("📊 Celery worker is processing background tasks")
            print("\nPress Ctrl+C to stop all services")
            
            # Start Flask app (this will block)
            self.start_flask_app()
            
        except KeyboardInterrupt:
            print("\n⏹️  Shutdown requested by user")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
        finally:
            self.cleanup()

def main():
    """Main function"""
    manager = ServiceManager()
    manager.run()

if __name__ == '__main__':
    main()
