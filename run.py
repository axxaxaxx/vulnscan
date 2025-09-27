#!/usr/bin/env python3
"""
Production runner for the vulnerability scanner web application
"""

import os
import sys
from app import create_app

def main():
    """Main entry point for the application"""
    # Add the project root to Python path
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)
    
    # Create application
    app, celery = create_app()
    
    # Run the application
    if __name__ == '__main__':
        # Check if we're running in production mode
        if os.getenv('FLASK_ENV') == 'production':
            # Use Gunicorn for production
            from gunicorn.app.wsgiapp import WSGIApplication
            from gunicorn.workers import EventletWorker
            
            class StandaloneApplication(WSGIApplication):
                def init(self, parser, opts, args):
                    self.cfg.set('bind', '0.0.0.0:5000')
                    self.cfg.set('workers', 1)
                    self.cfg.set('worker_class', 'eventlet')
                    self.cfg.set('worker_connections', 1000)
                    self.cfg.set('timeout', 30)
                    self.cfg.set('keepalive', 2)
                    self.cfg.set('max_requests', 1000)
                    self.cfg.set('max_requests_jitter', 100)
                    self.cfg.set('preload_app', True)
            
            StandaloneApplication().run()
        else:
            # Use Flask development server
            app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    main()
