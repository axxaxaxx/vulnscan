#!/usr/bin/env python3
"""
Test script to verify monitoring page fix
"""

import requests
import sys

def test_monitoring_page():
    """Test the monitoring page"""
    print("🧪 Testing monitoring page...")
    
    try:
        # Test monitoring page
        response = requests.get('http://localhost:5000/monitoring')
        
        if response.status_code == 200:
            print("✅ Monitoring page loads successfully")
            
            # Check if the page contains expected content
            content = response.text
            if 'system_stats' in content or 'CPU Usage' in content:
                print("✅ Monitoring page contains expected content")
            else:
                print("⚠️  Monitoring page content may be incomplete")
            
            return True
        else:
            print(f"❌ Monitoring page failed with status: {response.status_code}")
            print(f"Response: {response.text[:500]}...")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
        return False
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

def test_psutil_availability():
    """Test if psutil is available"""
    print("\n🧪 Testing psutil availability...")
    
    try:
        import psutil
        print("✅ psutil is available")
        
        # Test basic psutil functionality
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        print(f"   CPU: {cpu_percent}%")
        print(f"   Memory: {memory.percent}%")
        print(f"   Disk: {disk.percent}%")
        
        return True
        
    except ImportError:
        print("❌ psutil is not installed")
        print("   Install with: pip install psutil")
        return False
    except Exception as e:
        print(f"❌ psutil test failed: {e}")
        return False

def main():
    """Run monitoring tests"""
    print("=" * 60)
    print("🔧 MONITORING PAGE FIX TEST")
    print("=" * 60)
    
    # Test 1: psutil availability
    psutil_ok = test_psutil_availability()
    
    # Test 2: monitoring page
    monitoring_ok = test_monitoring_page()
    
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS")
    print("=" * 60)
    print(f"psutil Availability: {'✅ PASS' if psutil_ok else '❌ FAIL'}")
    print(f"Monitoring Page: {'✅ PASS' if monitoring_ok else '❌ FAIL'}")
    
    if monitoring_ok:
        print("\n🎉 MONITORING PAGE IS WORKING!")
        print("You can now access the monitoring page at http://localhost:5000/monitoring")
    else:
        print("\n❌ MONITORING PAGE HAS ISSUES")
        if not psutil_ok:
            print("🔧 SOLUTION: Install psutil")
            print("   pip install psutil")
        else:
            print("🔧 SOLUTION: Check the Flask application logs for more details")

if __name__ == '__main__':
    main()
