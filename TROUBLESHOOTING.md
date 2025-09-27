# Troubleshooting Guide

This guide helps resolve common issues when setting up and running the Vulnerability Scanner Web Application.

## Common Issues and Solutions

### 1. Import Errors

#### Error: `ModuleNotFoundError: No module named 'app.routes'`

**Solution:**
```bash
# Make sure you're in the project root directory
cd vulnerabilityScannerWebApp

# Check that all __init__.py files exist
ls -la app/
ls -la app/routes/
ls -la app/modules/
ls -la app/tasks/

# If missing, create them:
touch app/__init__.py
touch app/routes/__init__.py
touch app/modules/__init__.py
touch app/tasks/__init__.py
```

#### Error: `ImportError: cannot import name 'main_bp' from 'app.routes'`

**Solution:**
The `app/routes/__init__.py` file should contain:
```python
from .main import main_bp
from .api import api_bp
from .scan import scan_bp
from .report import report_bp
from .monitor import monitor_bp

__all__ = ['main_bp', 'api_bp', 'scan_bp', 'report_bp', 'monitor_bp']
```

### 2. Flask CLI Issues

#### Error: `Error: Could not locate a Flask application`

**Solution:**
```bash
# Set the Flask app environment variable
export FLASK_APP=flask_app.py

# Or use the full path
export FLASK_APP=/path/to/vulnerabilityScannerWebApp/flask_app.py

# Then run Flask commands
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### 3. Database Issues

#### Error: `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) no such table`

**Solution:**
```bash
# Activate virtual environment
source venv/bin/activate

# Set Flask app
export FLASK_APP=flask_app.py

# Initialize and migrate database
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### 4. Redis Connection Issues

#### Error: `redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379`

**Solution:**
```bash
# Start Redis server
redis-server

# Or on Ubuntu/Debian
sudo systemctl start redis-server

# Or on macOS with Homebrew
brew services start redis

# Test connection
redis-cli ping
# Should return: PONG
```

### 5. Celery Issues

#### Error: `celery.exceptions.NotConfigured: No celery configuration found`

**Solution:**
```bash
# Make sure you're in the project root
cd vulnerabilityScannerWebApp

# Activate virtual environment
source venv/bin/activate

# Start Celery worker
celery -A app.celery worker --loglevel=info
```

### 6. Permission Issues

#### Error: `Permission denied` when running setup.sh

**Solution:**
```bash
# Make the script executable
chmod +x setup.sh

# Run the script
./setup.sh
```

### 7. Python Version Issues

#### Error: `python: command not found` or wrong Python version

**Solution:**
```bash
# Check Python version
python3 --version

# Should be 3.8 or higher
# If not installed, install Python 3.8+

# On Ubuntu/Debian
sudo apt update
sudo apt install python3.8 python3.8-venv python3.8-pip

# On macOS with Homebrew
brew install python@3.9

# On CentOS/RHEL
sudo yum install python38 python38-pip
```

### 8. Missing Dependencies

#### Error: `ModuleNotFoundError: No module named 'flask'`

**Solution:**
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Or install individually
pip install flask flask-sqlalchemy flask-socketio celery redis python-nmap beautifulsoup4
```

### 9. WeasyPrint Issues

#### Error: `WeasyPrint could not import some external libraries` or `OSError: cannot load library 'pango-1.0-0'`

**Solution:**

**Option 1: Smart Package Detection (Recommended)**
```bash
# Run the smart package detection script
chmod +x detect_packages.sh
./detect_packages.sh
```

**Option 2: Standard Fix Script**
```bash
# Run the WeasyPrint fix script
chmod +x fix_weasyprint.sh
./fix_weasyprint.sh
```

**Option 3: Manual Installation**

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info libcairo2 libcairo-gobject2 libpangocairo-1.0-0 python3-dev libxml2-dev libxslt1-dev zlib1g-dev libjpeg-dev libpng-dev libfreetype6-dev libharfbuzz-dev libfribidi-dev
```

On CentOS/RHEL/Fedora:
```bash
sudo yum install -y pango gdk-pixbuf2 libffi-devel shared-mime-info cairo cairo-gobject pango-devel python3-devel libxml2-devel libxslt-devel zlib-devel libjpeg-devel libpng-devel freetype-devel harfbuzz-devel fribidi-devel
```

On macOS:
```bash
brew install pango gdk-pixbuf cairo libffi libxml2 libxslt
```

Then reinstall WeasyPrint:
```bash
pip uninstall -y weasyprint
pip install weasyprint
```

#### Error: `No PDF generation engines available`

**Solution:**
The application will fall back to ReportLab if WeasyPrint is not available. To enable PDF generation:

```bash
# Install WeasyPrint dependencies (see above)
# Or use ReportLab only by modifying requirements.txt
```

## Debugging Steps

### 1. Check Installation
```bash
# Run the test script
python test_installation.py
```

### 2. Check Environment
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Check installed packages
pip list

# Check environment variables
echo $FLASK_APP
echo $DATABASE_URL
```

### 3. Check Logs
```bash
# Check application logs
tail -f logs/vuln_scanner.log

# Check Redis logs
tail -f /var/log/redis/redis-server.log

# Check system logs
journalctl -u redis-server
```

### 4. Manual Testing
```bash
# Test Python imports
python3 -c "from app import create_app; print('App created successfully')"

# Test database connection
python3 -c "from app import create_app, db; app, _ = create_app(); app.app_context().push(); print('Database connected')"

# Test Redis connection
python3 -c "import redis; r = redis.Redis(); print(r.ping())"
```

## Getting Help

If you're still experiencing issues:

1. **Check the logs** in the `logs/` directory
2. **Run the test script** to identify specific problems
3. **Check system requirements** (Python 3.8+, Redis, Nmap)
4. **Verify file permissions** and directory structure
5. **Check network connectivity** for external services

## File Structure

Make sure your project has this structure:
```
vulnerabilityScannerWebApp/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── api.py
│   │   ├── scan.py
│   │   ├── report.py
│   │   └── monitor.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── nmap_scanner.py
│   │   ├── cve_lookup.py
│   │   └── ...
│   └── tasks/
│       ├── __init__.py
│       └── scan_tasks.py
├── tests/
├── app.py
├── flask_app.py
├── setup.sh
├── requirements.txt
└── README.md
```
