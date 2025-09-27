#!/usr/bin/env python3
"""
Verification script for Basic Scan configuration
"""

from app import create_app, db
from app.models import ScanType

def verify_basic_scan():
    """Verify Basic Scan configuration"""
    try:
        app, celery = create_app()
        
        with app.app_context():
            # Create database tables
            db.create_all()
            
            # Initialize default scan types
            from app.modules.scan_type_initializer import ensure_default_scan_types
            ensure_default_scan_types()
            
            # Get Basic Scan
            basic_scan = ScanType.query.filter_by(name='Basic Scan').first()
            if not basic_scan:
                print("❌ Basic Scan not found!")
                return False
            
            print("✅ Basic Scan Configuration Verified:")
            print(f"  📍 Port Range: {basic_scan.get_port_range()}")
            print(f"  🔧 Nmap Arguments: {basic_scan.nmap_arguments}")
            print(f"  🔍 Searchsploit: {basic_scan.enable_searchsploit}")
            print(f"  📊 CVE Lookup: {basic_scan.enable_cve_lookup}")
            print(f"  🌐 OSINT: {basic_scan.enable_osint}")
            print(f"  📋 Compliance Check: {basic_scan.enable_compliance_check}")
            
            # Test nmap command
            test_target = "192.168.1.1"
            nmap_cmd = basic_scan.get_full_nmap_command(test_target)
            print(f"\n🎯 Generated Nmap Command:")
            print(f"  {nmap_cmd}")
            
            # Verify configuration
            if (basic_scan.enable_searchsploit == True and 
                basic_scan.enable_cve_lookup == False and 
                basic_scan.enable_osint == False and 
                basic_scan.enable_compliance_check == False):
                print("\n✅ Basic Scan configuration is correct!")
                print("   - Only ports scanning and searchsploit enabled")
                return True
            else:
                print("\n❌ Basic Scan configuration is incorrect!")
                return False
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    verify_basic_scan()
