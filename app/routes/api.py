"""
API routes
Handles REST API endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from flask_socketio import emit
from app import db
from app.models import Scan, Customer, Vulnerability, Port, ComplianceIssue, SystemLog
from app.modules.logger import get_logger
from app.modules.pdf_generator import PDFGenerator
import json

api_bp = Blueprint('api', __name__)
logger = get_logger(__name__)

@api_bp.route('/customers', methods=['GET'])
def get_customers():
    """Get all customers"""
    try:
        customers = Customer.query.all()
        return jsonify([customer.to_dict() for customer in customers])
    
    except Exception as e:
        logger.error(f"Error getting customers: {str(e)}")
        return jsonify({'error': 'Failed to get customers'}), 500

@api_bp.route('/customers', methods=['POST'])
def create_customer():
    """Create a new customer"""
    try:
        data = request.get_json()
        
        if not data or not data.get('name') or not data.get('email'):
            return jsonify({'error': 'Name and email are required'}), 400
        
        customer = Customer(
            name=data['name'],
            email=data['email'],
            organization=data.get('organization', '')
        )
        
        db.session.add(customer)
        db.session.commit()
        
        logger.info(f"Created customer: {customer.name}")
        return jsonify(customer.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating customer: {str(e)}")
        return jsonify({'error': 'Failed to create customer'}), 500

@api_bp.route('/customers/<int:customer_id>', methods=['GET'])
def get_customer(customer_id):
    """Get a specific customer"""
    try:
        customer = Customer.query.get_or_404(customer_id)
        return jsonify(customer.to_dict())
    
    except Exception as e:
        logger.error(f"Error getting customer {customer_id}: {str(e)}")
        return jsonify({'error': 'Customer not found'}), 404

@api_bp.route('/customers/<int:customer_id>', methods=['PUT'])
def update_customer(customer_id):
    """Update a customer"""
    try:
        customer = Customer.query.get_or_404(customer_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'name' in data:
            customer.name = data['name']
        if 'email' in data:
            customer.email = data['email']
        if 'organization' in data:
            customer.organization = data['organization']
        
        db.session.commit()
        
        logger.info(f"Updated customer: {customer.name}")
        return jsonify(customer.to_dict())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating customer {customer_id}: {str(e)}")
        return jsonify({'error': 'Failed to update customer'}), 500

@api_bp.route('/customers/<int:customer_id>', methods=['DELETE'])
def delete_customer(customer_id):
    """Delete a customer"""
    try:
        customer = Customer.query.get_or_404(customer_id)
        
        # Check if customer has scans
        if Scan.query.filter_by(customer_id=customer_id).count() > 0:
            return jsonify({'error': 'Cannot delete customer with existing scans'}), 400
        
        db.session.delete(customer)
        db.session.commit()
        
        logger.info(f"Deleted customer: {customer.name}")
        return jsonify({'message': 'Customer deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting customer {customer_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete customer'}), 500

@api_bp.route('/scans', methods=['GET'])
def get_scans():
    """Get all scans with optional filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        customer_id = request.args.get('customer_id', type=int)
        
        query = Scan.query
        
        if status:
            query = query.filter_by(status=status)
        if customer_id:
            query = query.filter_by(customer_id=customer_id)
        
        scans = query.order_by(Scan.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans.items],
            'total': scans.total,
            'pages': scans.pages,
            'current_page': scans.page,
            'per_page': scans.per_page
        })
    
    except Exception as e:
        logger.error(f"Error getting scans: {str(e)}")
        return jsonify({'error': 'Failed to get scans'}), 500

@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get a specific scan with details"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        customer = Customer.query.get(scan.customer_id)
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        ports = Port.query.filter_by(scan_id=scan_id).all()
        compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
        
        scan_data = scan.to_dict()
        scan_data['customer'] = customer.to_dict() if customer else None
        scan_data['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
        scan_data['ports'] = [p.to_dict() for p in ports]
        scan_data['compliance_issues'] = [c.to_dict() for c in compliance_issues]
        
        return jsonify(scan_data)
    
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Scan not found'}), 404

@api_bp.route('/scans/<int:scan_id>/vulnerabilities', methods=['GET'])
def get_scan_vulnerabilities(scan_id):
    """Get vulnerabilities for a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        return jsonify([v.to_dict() for v in vulnerabilities])
    
    except Exception as e:
        logger.error(f"Error getting vulnerabilities for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get vulnerabilities'}), 500

@api_bp.route('/scans/<int:scan_id>/ports', methods=['GET'])
def get_scan_ports(scan_id):
    """Get ports for a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        ports = Port.query.filter_by(scan_id=scan_id).all()
        
        return jsonify([p.to_dict() for p in ports])
    
    except Exception as e:
        logger.error(f"Error getting ports for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get ports'}), 500

@api_bp.route('/scans/<int:scan_id>/compliance', methods=['GET'])
def get_scan_compliance(scan_id):
    """Get compliance issues for a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
        
        return jsonify([c.to_dict() for c in compliance_issues])
    
    except Exception as e:
        logger.error(f"Error getting compliance issues for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get compliance issues'}), 500

@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['PUT'])
def update_vulnerability(vuln_id):
    """Update a vulnerability"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vuln_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'status' in data:
            vulnerability.status = data['status']
        if 'remediation' in data:
            vulnerability.remediation = data['remediation']
        
        db.session.commit()
        
        logger.info(f"Updated vulnerability {vuln_id}")
        return jsonify(vulnerability.to_dict())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating vulnerability {vuln_id}: {str(e)}")
        return jsonify({'error': 'Failed to update vulnerability'}), 500

@api_bp.route('/compliance/<int:compliance_id>', methods=['PUT'])
def update_compliance_issue(compliance_id):
    """Update a compliance issue"""
    try:
        compliance_issue = ComplianceIssue.query.get_or_404(compliance_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'status' in data:
            compliance_issue.status = data['status']
        if 'recommendation' in data:
            compliance_issue.recommendation = data['recommendation']
        
        db.session.commit()
        
        logger.info(f"Updated compliance issue {compliance_id}")
        return jsonify(compliance_issue.to_dict())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating compliance issue {compliance_id}: {str(e)}")
        return jsonify({'error': 'Failed to update compliance issue'}), 500

@api_bp.route('/system/stats', methods=['GET'])
def get_system_stats():
    """Get system statistics"""
    try:
        import psutil
        
        stats = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'boot_time': psutil.boot_time(),
            'total_scans': Scan.query.count(),
            'active_scans': Scan.query.filter(Scan.status.in_(['pending', 'running'])).count(),
            'total_vulnerabilities': Vulnerability.query.count(),
            'total_compliance_issues': ComplianceIssue.query.count()
        }
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}")
        return jsonify({'error': 'Failed to get system stats'}), 500

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get system logs"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        level = request.args.get('level')
        component = request.args.get('component')
        
        query = SystemLog.query
        
        if level:
            query = query.filter_by(level=level)
        if component:
            query = query.filter_by(component=component)
        
        logs = query.order_by(SystemLog.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'current_page': logs.page,
            'per_page': logs.per_page
        })
    
    except Exception as e:
        logger.error(f"Error getting logs: {str(e)}")
        return jsonify({'error': 'Failed to get logs'}), 500

# Scan API endpoints (for frontend compatibility)
@api_bp.route('/scans', methods=['GET'])
def api_get_scans():
    """Get all scans via API"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        scans = Scan.query.order_by(Scan.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans.items],
            'total': scans.total,
            'pages': scans.pages,
            'current_page': scans.page,
            'per_page': scans.per_page
        })
    
    except Exception as e:
        logger.error(f"Error getting scans: {str(e)}")
        return jsonify({'error': 'Failed to get scans'}), 500

@api_bp.route('/scans', methods=['POST'])
def api_create_scan():
    """Create a new scan via API"""
    try:
        data = request.get_json()
        
        if not data or not data.get('customer_id') or not data.get('target'):
            return jsonify({'error': 'Customer ID and target are required'}), 400
        
        # Validate customer exists
        customer = Customer.query.get(data['customer_id'])
        if not customer:
            return jsonify({'error': 'Customer not found'}), 404
        
        scan = Scan(
            customer_id=data['customer_id'],
            name=data.get('name', f"Scan of {data['target']}"),
            target=data['target'],
            scan_type=data.get('scan_type', 'comprehensive'),
            enable_cve_lookup=data.get('enable_cve_lookup', False),
            enable_osint=data.get('enable_osint', False)
        )
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info(f"Created scan: {scan.name}")
        return jsonify(scan.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating scan: {str(e)}")
        return jsonify({'error': 'Failed to create scan'}), 500

@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
def api_get_scan(scan_id):
    """Get a specific scan via API"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        return jsonify(scan.to_dict())
    
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Scan not found'}), 404

@api_bp.route('/scans/<int:scan_id>', methods=['PUT'])
def api_update_scan(scan_id):
    """Update a scan via API"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'name' in data:
            scan.name = data['name']
        if 'target' in data:
            scan.target = data['target']
        if 'scan_type' in data:
            scan.scan_type = data['scan_type']
        if 'enable_cve_lookup' in data:
            scan.enable_cve_lookup = data['enable_cve_lookup']
        if 'enable_osint' in data:
            scan.enable_osint = data['enable_osint']
        
        db.session.commit()
        
        logger.info(f"Updated scan: {scan.name}")
        return jsonify(scan.to_dict())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to update scan'}), 500

@api_bp.route('/scans/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    """Delete a scan via API"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # Delete related data
        Vulnerability.query.filter_by(scan_id=scan_id).delete()
        Port.query.filter_by(scan_id=scan_id).delete()
        ComplianceIssue.query.filter_by(scan_id=scan_id).delete()
        
        db.session.delete(scan)
        db.session.commit()
        
        logger.info(f"Deleted scan: {scan.name}")
        return jsonify({'message': 'Scan deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete scan'}), 500

@api_bp.route('/scans/<int:scan_id>/start', methods=['POST'])
def api_start_scan(scan_id):
    """Start a scan via API"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        if scan.status != 'pending':
            return jsonify({'error': f'Scan is already {scan.status}'}), 400
        
        # Update scan status
        scan.status = 'running'
        scan.started_at = db.func.now()
        db.session.commit()
        
        # Execute scan synchronously using OS tools
        try:
            logger.info(f"Starting synchronous scan execution for scan {scan_id}")
            
            # Import scanning modules
            from app.modules.nmap_scanner import NmapScanner
            from app.modules.cve_lookup import CVELookup
            from app.modules.osint_scanner import OSINTScanner
            from app.modules.compliance_checker import ComplianceChecker
            from app.models import Port, Vulnerability, ComplianceIssue
            
            # Step 1: Nmap Scan
            logger.info(f"Running Nmap scan on {scan.target}")
            scan.progress = 10
            db.session.commit()
            
            scanner = NmapScanner()
            nmap_result = scanner.scan_target(scan.target)
            
            # Save port results to database
            if nmap_result and 'ports' in nmap_result:
                for port_data in nmap_result['ports']:
                    port = Port(
                        scan_id=scan_id,
                        port_number=port_data.get('port'),
                        protocol=port_data.get('protocol', 'tcp'),
                        state=port_data.get('state', 'open'),
                        service=port_data.get('service', 'unknown'),
                        version=port_data.get('version', ''),
                        banner=port_data.get('banner', '')
                    )
                    db.session.add(port)
            
            scan.progress = 40
            db.session.commit()
            
            # Step 2: CVE Lookup (if enabled)
            if scan.enable_cve_lookup:
                logger.info(f"Running CVE lookup for scan {scan_id}")
                try:
                    cve_lookup = CVELookup()
                    cve_results = cve_lookup.lookup_cves(scan.target)
                    
                    # Save CVE results to database
                    if cve_results:
                        for cve_data in cve_results:
                            vulnerability = Vulnerability(
                                scan_id=scan_id,
                                cve_id=cve_data.get('cve_id'),
                                title=cve_data.get('title', ''),
                                description=cve_data.get('description', ''),
                                severity=cve_data.get('severity', 'info'),
                                cvss_score=cve_data.get('cvss_score', 0.0),
                                references=cve_data.get('references', '')
                            )
                            db.session.add(vulnerability)
                except Exception as cve_error:
                    logger.warning(f"CVE lookup failed: {cve_error}")
            
            scan.progress = 70
            db.session.commit()
            
            # Step 3: OSINT Scan (if enabled)
            if scan.enable_osint:
                logger.info(f"Running OSINT scan for scan {scan_id}")
                try:
                    osint_scanner = OSINTScanner()
                    osint_results = osint_scanner.scan_target(scan.target)
                    # OSINT results could be stored in a separate table or as scan metadata
                except Exception as osint_error:
                    logger.warning(f"OSINT scan failed: {osint_error}")
            
            scan.progress = 85
            db.session.commit()
            
            # Step 4: Compliance Check (if enabled)
            if scan.enable_compliance_check:
                logger.info(f"Running compliance check for scan {scan_id}")
                try:
                    compliance_checker = ComplianceChecker()
                    ports = Port.query.filter_by(scan_id=scan_id).all()
                    compliance_results = compliance_checker.check_compliance(ports)
                    
                    # Save compliance issues to database
                    if compliance_results:
                        for issue_data in compliance_results:
                            compliance_issue = ComplianceIssue(
                                scan_id=scan_id,
                                category=issue_data.get('category', ''),
                                severity=issue_data.get('severity', 'medium'),
                                description=issue_data.get('description', ''),
                                recommendation=issue_data.get('recommendation', '')
                            )
                            db.session.add(compliance_issue)
                except Exception as compliance_error:
                    logger.warning(f"Compliance check failed: {compliance_error}")
            
            # Mark scan as completed
            scan.status = 'completed'
            scan.progress = 100
            scan.completed_at = db.func.now()
            db.session.commit()
            
            logger.info(f"Completed scan: {scan.name}")
            return jsonify(scan.to_dict())
            
        except Exception as scan_error:
            # If scan execution fails, mark as failed
            logger.error(f"Failed to execute scan {scan_id}: {scan_error}")
            scan.status = 'failed'
            scan.completed_at = db.func.now()
            db.session.commit()
            return jsonify({'error': f'Failed to execute scan: {str(scan_error)}'}), 500
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error starting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to start scan'}), 500

@api_bp.route('/scans/reset-stuck', methods=['POST'])
def reset_stuck_scans():
    """Reset scans that have been stuck in running state for too long"""
    try:
        from datetime import datetime, timedelta
        
        # Find scans that have been running for more than 30 minutes
        timeout_threshold = datetime.utcnow() - timedelta(minutes=30)
        stuck_scans = Scan.query.filter(
            Scan.status == 'running',
            Scan.started_at < timeout_threshold
        ).all()
        
        reset_count = 0
        for scan in stuck_scans:
            scan.status = 'failed'
            scan.completed_at = db.func.now()
            reset_count += 1
            logger.warning(f"Reset stuck scan {scan.id}: {scan.name}")
        
        db.session.commit()
        
        return jsonify({
            'message': f'Reset {reset_count} stuck scans',
            'reset_count': reset_count
        })
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error resetting stuck scans: {str(e)}")
        return jsonify({'error': 'Failed to reset stuck scans'}), 500

@api_bp.route('/scans/<int:scan_id>/stop', methods=['POST'])
def api_stop_scan(scan_id):
    """Stop a running scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        if scan.status != 'running':
            return jsonify({'error': f'Scan is not running (status: {scan.status})'}), 400
        
        # Update scan status to failed
        scan.status = 'failed'
        scan.completed_at = db.func.now()
        db.session.commit()
        
        logger.info(f"Stopped scan: {scan.name}")
        return jsonify(scan.to_dict())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error stopping scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to stop scan'}), 500

# Monitoring API endpoints
@api_bp.route('/monitoring/stats', methods=['GET'])
def get_monitoring_stats():
    """Get system monitoring statistics"""
    try:
        # Get system statistics
        try:
            import psutil
            
            system_stats = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'boot_time': psutil.boot_time()
            }
        except ImportError:
            # Fallback if psutil is not available
            system_stats = {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_percent': 0,
                'boot_time': 0
            }
        
        # Get active scans count
        active_scans_count = Scan.query.filter(Scan.status.in_(['pending', 'running'])).count()
        
        # Get recent logs count
        recent_logs_count = SystemLog.query.count()
        
        return jsonify({
            'system_stats': system_stats,
            'active_scans_count': active_scans_count,
            'recent_logs_count': recent_logs_count
        })
    
    except Exception as e:
        logger.error(f"Error getting monitoring stats: {str(e)}")
        return jsonify({'error': 'Failed to get monitoring stats'}), 500
