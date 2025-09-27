#!/usr/bin/env python3
"""
Fix script for duplicate route conflicts
Run this script in your remote environment to resolve duplicate route issues
"""

import os
import sys
import subprocess

def fix_duplicate_routes():
    """Fix duplicate route conflicts"""
    print("🔧 Fixing duplicate route conflicts...")
    
    try:
        # Step 1: Pull latest changes
        print("📥 Pulling latest changes from GitHub...")
        result = subprocess.run(['git', 'pull', 'origin', 'main'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Git pull failed: {result.stderr}")
            return False
        print("✅ Latest changes pulled successfully")
        
        # Step 2: Clear Python cache
        print("🧹 Clearing Python cache...")
        cache_dirs = []
        for root, dirs, files in os.walk('.'):
            if '__pycache__' in dirs:
                cache_dirs.append(os.path.join(root, '__pycache__'))
            for file in files:
                if file.endswith('.pyc'):
                    os.remove(os.path.join(root, file))
        
        for cache_dir in cache_dirs:
            subprocess.run(['rm', '-rf', cache_dir])
        print("✅ Python cache cleared")
        
        # Step 3: Check for duplicate routes
        print("🔍 Checking for duplicate routes...")
        try:
            from app import create_app
            app, celery = create_app()
            
            scan_detail_routes = []
            for rule in app.url_map.iter_rules():
                if 'scan_detail' in rule.endpoint:
                    scan_detail_routes.append(f"{rule.rule} -> {rule.endpoint}")
            
            if len(scan_detail_routes) == 1:
                print(f"✅ Only one scan_detail route found: {scan_detail_routes[0]}")
                print("✅ Duplicate route issue resolved!")
                return True
            else:
                print(f"❌ Found {len(scan_detail_routes)} scan_detail routes:")
                for route in scan_detail_routes:
                    print(f"  - {route}")
                return False
                
        except Exception as e:
            print(f"❌ Error checking routes: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Error during fix: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Starting duplicate route fix...")
    
    if fix_duplicate_routes():
        print("\n🎉 Fix completed successfully!")
        print("You can now start the application with: python app.py")
    else:
        print("\n❌ Fix failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
