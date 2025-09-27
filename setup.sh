#!/bin/bash

# Vulnerability Scanner Web Application Setup Script
# This script automates the complete setup process for first-time installation

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        REQUIRED_VERSION="3.8"
        
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            print_success "Python $PYTHON_VERSION found (>= $REQUIRED_VERSION required)"
            return 0
        else
            print_error "Python $PYTHON_VERSION found, but version $REQUIRED_VERSION or higher is required"
            return 1
        fi
    else
        print_error "Python 3 is not installed. Please install Python 3.8 or higher."
        return 1
    fi
}

# Function to check if Redis is running
check_redis() {
    if command_exists redis-cli; then
        if redis-cli ping >/dev/null 2>&1; then
            print_success "Redis is running"
            return 0
        else
            print_warning "Redis is installed but not running. Starting Redis..."
            if command_exists systemctl; then
                sudo systemctl start redis
            elif command_exists brew; then
                brew services start redis
            else
                print_warning "Please start Redis manually: redis-server"
                return 1
            fi
        fi
    else
        print_warning "Redis is not installed. Installing Redis..."
        if command_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y redis-server
        elif command_exists yum; then
            sudo yum install -y redis
        elif command_exists brew; then
            brew install redis
        else
            print_error "Cannot install Redis automatically. Please install Redis manually."
            return 1
        fi
    fi
}

# Function to check if Nmap is installed
check_nmap() {
    if command_exists nmap; then
        print_success "Nmap is installed"
        return 0
    else
        print_warning "Nmap is not installed. Installing Nmap..."
        if command_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y nmap
        elif command_exists yum; then
            sudo yum install -y nmap
        elif command_exists brew; then
            brew install nmap
        else
            print_error "Cannot install Nmap automatically. Please install Nmap manually."
            return 1
        fi
    fi
}

# Function to install WeasyPrint system dependencies
install_weasyprint_deps() {
    print_status "Installing WeasyPrint system dependencies..."
    
    if command_exists apt-get; then
        # Ubuntu/Debian - try different package name variations
        sudo apt-get update
        
        # Try to install packages with fallback names
        print_status "Installing core WeasyPrint dependencies..."
        sudo apt-get install -y \
            libpango-1.0-0 \
            libpangoft2-1.0-0 \
            libgdk-pixbuf-2.0-0 \
            libffi-dev \
            shared-mime-info \
            libcairo2 \
            libcairo-gobject2 \
            libpangocairo-1.0-0 \
            python3-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            libjpeg-dev \
            libpng-dev \
            libfreetype6-dev \
            libharfbuzz-dev \
            libfribidi-dev || {
            print_warning "Some packages failed to install, trying alternative names..."
            # Try alternative package names
            sudo apt-get install -y \
                libpango1.0-dev \
                libgdk-pixbuf2.0-dev \
                libcairo2-dev \
                libffi-dev \
                shared-mime-info \
                python3-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                libjpeg-dev \
                libpng-dev \
                libfreetype6-dev \
                libharfbuzz-dev \
                libfribidi-dev
        }
        print_success "WeasyPrint dependencies installed"
    elif command_exists yum; then
        # CentOS/RHEL/Fedora
        sudo yum install -y \
            pango \
            gdk-pixbuf2 \
            libffi-devel \
            shared-mime-info \
            cairo \
            cairo-gobject \
            pango-devel \
            python3-devel \
            libxml2-devel \
            libxslt-devel \
            zlib-devel \
            libjpeg-devel \
            libpng-devel \
            freetype-devel \
            harfbuzz-devel \
            fribidi-devel
        print_success "WeasyPrint dependencies installed"
    elif command_exists brew; then
        # macOS
        brew install pango gdk-pixbuf cairo libffi libxml2 libxslt
        print_success "WeasyPrint dependencies installed"
    else
        print_warning "Cannot install WeasyPrint dependencies automatically. Please install them manually."
        print_warning "Required packages: pango, gdk-pixbuf, cairo, libffi, libxml2, libxslt"
        return 1
    fi
}

# Function to setup Python virtual environment
setup_virtualenv() {
    print_status "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    print_success "Virtual environment activated"
    
    # Upgrade pip
    pip install --upgrade pip
    print_success "Pip upgraded to latest version"
}

# Function to install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Function to setup environment variables
setup_environment() {
    print_status "Setting up environment variables..."
    
    if [ ! -f ".env" ]; then
        if [ -f "env.example" ]; then
            cp env.example .env
            print_success "Environment file created from template"
        else
            # Create basic .env file
            cat > .env << EOF
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_URL=sqlite:///vuln_scanner.db
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
EOF
            print_success "Environment file created with default values"
        fi
    else
        print_status "Environment file already exists"
    fi
}

# Function to initialize database
init_database() {
    print_status "Initializing database..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Set Flask app environment variable
    export FLASK_APP=flask_app.py
    
    # Initialize Flask-Migrate
    if [ ! -d "migrations" ]; then
        flask db init
        print_success "Database migration initialized"
    else
        print_status "Database migration already initialized"
    fi
    
    # Create migration
    flask db migrate -m "Initial migration"
    print_success "Database migration created"
    
    # Apply migration
    flask db upgrade
    print_success "Database tables created"
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p reports
    mkdir -p temp
    
    print_success "Directories created"
}

# Function to setup searchsploit (optional)
setup_searchsploit() {
    print_status "Setting up Searchsploit (optional)..."
    
    if command_exists searchsploit; then
        print_success "Searchsploit is already installed"
    else
        print_warning "Installing Searchsploit..."
        if [ ! -d "/opt/exploitdb" ]; then
            sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
            sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
            print_success "Searchsploit installed"
        else
            print_success "Searchsploit already exists"
        fi
    fi
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Run installation test first
    print_status "Running installation test..."
    python test_installation.py
    
    # Run SQLAlchemy compatibility test
    print_status "Running SQLAlchemy compatibility test..."
    python test_sqlalchemy_compatibility.py
    
    if command_exists pytest; then
        pytest tests/ -v --tb=short
        print_success "Tests completed"
    else
        print_warning "pytest not found, skipping unit tests"
    fi
}

# Function to create startup scripts
create_startup_scripts() {
    print_status "Creating startup scripts..."
    
    # Create start script
    cat > start.sh << 'EOF'
#!/bin/bash
# Start the Vulnerability Scanner Web Application

echo "Starting Vulnerability Scanner Web Application..."

# Activate virtual environment
source venv/bin/activate

# Set Flask app environment variable
export FLASK_APP=flask_app.py

# Start Redis if not running
if ! redis-cli ping >/dev/null 2>&1; then
    echo "Starting Redis..."
    redis-server --daemonize yes
fi

# Start Celery worker in background
echo "Starting Celery worker..."
celery -A app.celery worker --loglevel=info --detach

# Start Flask application
echo "Starting Flask application..."
python app.py
EOF

    chmod +x start.sh
    
    # Create stop script
    cat > stop.sh << 'EOF'
#!/bin/bash
# Stop the Vulnerability Scanner Web Application

echo "Stopping Vulnerability Scanner Web Application..."

# Stop Celery workers
pkill -f "celery.*worker"

# Stop Redis if we started it
if pgrep -f "redis-server" >/dev/null; then
    echo "Stopping Redis..."
    pkill -f "redis-server"
fi

echo "Application stopped"
EOF

    chmod +x stop.sh
    
    print_success "Startup scripts created"
}

# Function to display final instructions
display_final_instructions() {
    print_success "Setup completed successfully!"
    echo
    echo "=========================================="
    echo "Vulnerability Scanner Web Application"
    echo "=========================================="
    echo
    echo "To start the application:"
    echo "  ./start.sh"
    echo
    echo "To stop the application:"
    echo "  ./stop.sh"
    echo
    echo "To run manually:"
    echo "  1. Activate virtual environment: source venv/bin/activate"
    echo "  2. Start Redis: redis-server"
    echo "  3. Start Celery worker: celery -A app.celery worker --loglevel=info"
    echo "  4. Start Flask app: python app.py"
    echo
    echo "The application will be available at: http://localhost:5000"
    echo
    echo "For production deployment, see README.md for Docker instructions."
    echo
}

# Main setup function
main() {
    echo "=========================================="
    echo "Vulnerability Scanner Web Application"
    echo "Setup Script"
    echo "=========================================="
    echo
    
    # Check system requirements
    print_status "Checking system requirements..."
    
    if ! check_python_version; then
        exit 1
    fi
    
    if ! check_redis; then
        print_warning "Redis setup failed, but continuing..."
    fi
    
    if ! check_nmap; then
        print_warning "Nmap setup failed, but continuing..."
    fi
    
    # Install WeasyPrint dependencies
    install_weasyprint_deps
    
    # Setup Python environment
    setup_virtualenv
    install_dependencies
    
    # Setup application
    setup_environment
    create_directories
    init_database
    setup_searchsploit
    
    # Create startup scripts
    create_startup_scripts
    
    # Run tests
    run_tests
    
    # Display final instructions
    display_final_instructions
}

# Run main function
main "$@"
