#!/bin/bash

# Package detection script for WeasyPrint dependencies
# This script finds the correct package names for your system

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

# Function to find package names
find_package() {
    local search_term="$1"
    local package_name=""
    
    if command_exists apt-cache; then
        package_name=$(apt-cache search "$search_term" | grep -E "^$search_term[^-]" | head -1 | awk '{print $1}')
    elif command_exists yum; then
        package_name=$(yum search "$search_term" 2>/dev/null | grep -E "^$search_term\." | head -1 | awk '{print $1}' | cut -d. -f1)
    elif command_exists dnf; then
        package_name=$(dnf search "$search_term" 2>/dev/null | grep -E "^$search_term\." | head -1 | awk '{print $1}' | cut -d. -f1)
    fi
    
    echo "$package_name"
}

print_status "Detecting WeasyPrint package names for your system..."

if command_exists apt-get; then
    print_status "Detected Ubuntu/Debian system"
    
    # Find the correct package names
    pango_pkg=$(find_package "libpango-1.0-0")
    if [ -z "$pango_pkg" ]; then
        pango_pkg=$(find_package "libpango1.0-0")
    fi
    if [ -z "$pango_pkg" ]; then
        pango_pkg="libpango-1.0-0"
    fi
    
    gdk_pixbuf_pkg=$(find_package "libgdk-pixbuf-2.0-0")
    if [ -z "$gdk_pixbuf_pkg" ]; then
        gdk_pixbuf_pkg=$(find_package "libgdk-pixbuf2.0-0")
    fi
    if [ -z "$gdk_pixbuf_pkg" ]; then
        gdk_pixbuf_pkg="libgdk-pixbuf-2.0-0"
    fi
    
    print_status "Found packages:"
    echo "  Pango: $pango_pkg"
    echo "  GDK-Pixbuf: $gdk_pixbuf_pkg"
    
    print_status "Installing WeasyPrint dependencies..."
    sudo apt-get update
    
    # Try to install with detected package names
    sudo apt-get install -y \
        $pango_pkg \
        libpangoft2-1.0-0 \
        $gdk_pixbuf_pkg \
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
        print_warning "Some packages failed, trying alternative approach..."
        
        # Try installing development packages instead
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
    
elif command_exists yum || command_exists dnf; then
    print_status "Detected CentOS/RHEL/Fedora system"
    
    if command_exists dnf; then
        PKG_MGR="dnf"
    else
        PKG_MGR="yum"
    fi
    
    sudo $PKG_MGR install -y \
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
    print_status "Detected macOS system"
    brew install pango gdk-pixbuf cairo libffi libxml2 libxslt
    print_success "WeasyPrint dependencies installed"
    
else
    print_error "Cannot detect package manager. Please install WeasyPrint dependencies manually."
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
