"""
Scan Type Initializer Module

This module handles the creation of default scan types when the application starts.
"""

from app import db
from app.models import ScanType
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

def create_default_scan_types():
    """
    Create default scan types if they don't exist.
    This function should be called during application initialization.
    """
    try:
        # Check if any scan types already exist
        existing_count = ScanType.query.count()
        if existing_count > 0:
            logger.info(f"Scan types already exist ({existing_count} found), skipping default creation")
            return
        
        logger.info("Creating default scan types...")
        
        # Basic Scan - Common ports only
        basic_scan = ScanType(
            name="Basic Scan",
            port_range_type="common",
            custom_ports=None,
            nmap_arguments="-sS -sV -O --script vuln",
            enable_searchsploit=False,
            enable_osint=False,
            enable_cve_lookup=True,
            enable_compliance_check=True,
            description="A quick scan of the most common ports (1-1000) with basic vulnerability detection. Perfect for initial reconnaissance and quick security assessments.",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Comprehensive Scan - All ports with all options
        comprehensive_scan = ScanType(
            name="Comprehensive Scan",
            port_range_type="all",
            custom_ports=None,
            nmap_arguments="-sS -sV -O -A --script vuln,discovery,exploit --script-timeout 30s",
            enable_searchsploit=True,
            enable_osint=True,
            enable_cve_lookup=True,
            enable_compliance_check=True,
            description="A thorough scan of all ports (1-65535) with comprehensive vulnerability detection, OSINT gathering, and compliance checking. Use for detailed security assessments and penetration testing.",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Add to database
        db.session.add(basic_scan)
        db.session.add(comprehensive_scan)
        db.session.commit()
        
        logger.info("Successfully created default scan types: Basic Scan and Comprehensive Scan")
        
    except Exception as e:
        logger.error(f"Error creating default scan types: {str(e)}")
        db.session.rollback()
        raise

def ensure_default_scan_types():
    """
    Ensure default scan types exist, create them if they don't.
    This is a safer version that won't fail if scan types already exist.
    """
    try:
        # Check if Basic Scan exists
        basic_scan = ScanType.query.filter_by(name="Basic Scan").first()
        if not basic_scan:
            logger.info("Creating Basic Scan type...")
            basic_scan = ScanType(
                name="Basic Scan",
                port_range_type="common",
                custom_ports=None,
                nmap_arguments="-sS -sV -O --script vuln",
                enable_searchsploit=False,
                enable_osint=False,
                enable_cve_lookup=True,
                enable_compliance_check=True,
                description="A quick scan of the most common ports (1-1000) with basic vulnerability detection. Perfect for initial reconnaissance and quick security assessments.",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db.session.add(basic_scan)
        
        # Check if Comprehensive Scan exists
        comprehensive_scan = ScanType.query.filter_by(name="Comprehensive Scan").first()
        if not comprehensive_scan:
            logger.info("Creating Comprehensive Scan type...")
            comprehensive_scan = ScanType(
                name="Comprehensive Scan",
                port_range_type="all",
                custom_ports=None,
                nmap_arguments="-sS -sV -O -A --script vuln,discovery,exploit --script-timeout 30s",
                enable_searchsploit=True,
                enable_osint=True,
                enable_cve_lookup=True,
                enable_compliance_check=True,
                description="A thorough scan of all ports (1-65535) with comprehensive vulnerability detection, OSINT gathering, and compliance checking. Use for detailed security assessments and penetration testing.",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db.session.add(comprehensive_scan)
        
        # Commit changes if any were made
        if not basic_scan or not comprehensive_scan:
            db.session.commit()
            logger.info("Successfully ensured default scan types exist")
        else:
            logger.info("Default scan types already exist")
            
    except Exception as e:
        logger.error(f"Error ensuring default scan types: {str(e)}")
        db.session.rollback()
        raise

def get_default_scan_types():
    """
    Get the default scan types for reference.
    Returns a list of dictionaries with the default scan type configurations.
    """
    return [
        {
            "name": "Basic Scan",
            "port_range_type": "common",
            "custom_ports": None,
            "nmap_arguments": "-sS -sV -O --script vuln",
            "enable_searchsploit": False,
            "enable_osint": False,
            "enable_cve_lookup": True,
            "enable_compliance_check": True,
            "description": "A quick scan of the most common ports (1-1000) with basic vulnerability detection. Perfect for initial reconnaissance and quick security assessments."
        },
        {
            "name": "Comprehensive Scan",
            "port_range_type": "all",
            "custom_ports": None,
            "nmap_arguments": "-sS -sV -O -A --script vuln,discovery,exploit --script-timeout 30s",
            "enable_searchsploit": True,
            "enable_osint": True,
            "enable_cve_lookup": True,
            "enable_compliance_check": True,
            "description": "A thorough scan of all ports (1-65535) with comprehensive vulnerability detection, OSINT gathering, and compliance checking. Use for detailed security assessments and penetration testing."
        }
    ]
