"""
Vulnerability Scanner Web Application Package
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_cors import CORS
from celery import Celery
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
socketio = SocketIO()
migrate = Migrate()

# Import celery from tasks module
from app.tasks.scan_tasks import celery

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///vuln_scanner.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    migrate.init_app(app, db)
    CORS(app)
    
    # Register blueprints
    from app.routes import main_bp, api_bp, scan_bp, report_bp, monitor_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(scan_bp, url_prefix='/scan')
    app.register_blueprint(report_bp, url_prefix='/report')
    app.register_blueprint(monitor_bp, url_prefix='/monitor')
    
    return app, celery
