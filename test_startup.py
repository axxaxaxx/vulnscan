#!/usr/bin/env python3
"""
Test script to verify application starts without route conflicts
"""

import sys
import os

def test_application_startup():
    """Test that the application can start without errors"""
    print("🧪 Testing application startup...")
    
    try:
        # Import the application
        from app import create_app, db
        
        print("✅ Application imports successfully")
        
        # Create app instance
        app, celery = create_app()
        print("✅ Application instance created successfully")
        
        # Test database initialization
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully")
        
        # Test route registration
        with app.app_context():
            # Get all registered routes
            routes = []
            for rule in app.url_map.iter_rules():
                routes.append(f"{rule.methods} {rule.rule}")
            
            print(f"✅ {len(routes)} routes registered successfully")
            
            # Check for duplicate routes
            route_signatures = set()
            duplicates = []
            
            for rule in app.url_map.iter_rules():
                signature = f"{rule.methods} {rule.rule}"
                if signature in route_signatures:
                    duplicates.append(signature)
                else:
                    route_signatures.add(signature)
            
            if duplicates:
                print(f"❌ Found duplicate routes: {duplicates}")
                return False
            else:
                print("✅ No duplicate routes found")
        
        print("\n🎉 Application startup test PASSED!")
        return True
        
    except Exception as e:
        print(f"❌ Application startup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run startup test"""
    print("=" * 60)
    print("🔧 APPLICATION STARTUP TEST")
    print("=" * 60)
    
    # Test application startup
    startup_ok = test_application_startup()
    
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS")
    print("=" * 60)
    print(f"Application Startup: {'✅ PASS' if startup_ok else '❌ FAIL'}")
    
    if startup_ok:
        print("\n🎉 APPLICATION STARTUP SUCCESSFUL!")
        print("You can now run the application with:")
        print("   python app.py")
        print("   or")
        print("   python start_all.py")
    else:
        print("\n❌ APPLICATION STARTUP FAILED")
        print("Please check the error messages above and fix any issues")

if __name__ == '__main__':
    main()