#!/bin/bash

# Quick fix script for WeasyPrint dependencies
# Run this if you're getting WeasyPrint import errors

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

print_status "Installing WeasyPrint system dependencies..."

if command_exists apt-get; then
    # Ubuntu/Debian
    print_status "Detected Ubuntu/Debian system"
    sudo apt-get update
    sudo apt-get install -y \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        shared-mime-info \
        libcairo2 \
        libcairo-gobject2 \
        libpango1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        shared-mime-info \
        python3-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev
    print_success "WeasyPrint dependencies installed for Ubuntu/Debian"
    
elif command_exists yum; then
    # CentOS/RHEL/Fedora
    print_status "Detected CentOS/RHEL/Fedora system"
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
        zlib-devel
    print_success "WeasyPrint dependencies installed for CentOS/RHEL/Fedora"
    
elif command_exists brew; then
    # macOS
    print_status "Detected macOS system"
    brew install pango gdk-pixbuf cairo libffi libxml2 libxslt
    print_success "WeasyPrint dependencies installed for macOS"
    
else
    print_error "Cannot detect package manager. Please install WeasyPrint dependencies manually:"
    print_error "Required packages: pango, gdk-pixbuf, cairo, libffi, libxml2, libxslt"
    exit 1
fi

print_status "Reinstalling WeasyPrint Python package..."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    print_status "Activated virtual environment"
fi

# Reinstall WeasyPrint
pip uninstall -y weasyprint || true
pip install weasyprint

print_success "WeasyPrint reinstalled successfully!"

print_status "Testing WeasyPrint import..."

python3 -c "
try:
    from weasyprint import HTML, CSS
    print('✅ WeasyPrint import successful!')
except Exception as e:
    print(f'❌ WeasyPrint import failed: {e}')
    exit(1)
"

print_success "WeasyPrint is now working correctly!"
print_status "You can now run the application: python app.py"
