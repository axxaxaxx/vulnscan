"""
Main web interface routes
Handles the main web pages and user interface
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_socketio import emit
from app import db
from app.models import Scan, Customer, Vulnerability, Port, ComplianceIssue, SystemLog
from app.modules.logger import get_logger
from datetime import datetime, timedelta
import json

main_bp = Blueprint('main', __name__)
logger = get_logger(__name__)

@main_bp.route('/')
def index():
    """Homepage with dashboard"""
    try:
        # Get recent scans
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
        
        # Get statistics
        total_scans = Scan.query.count()
        total_customers = Customer.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        total_compliance_issues = ComplianceIssue.query.count()
        
        # Get vulnerability counts by severity
        vuln_counts = {
            'critical': Vulnerability.query.filter_by(severity='critical').count(),
            'high': Vulnerability.query.filter_by(severity='high').count(),
            'medium': Vulnerability.query.filter_by(severity='medium').count(),
            'low': Vulnerability.query.filter_by(severity='low').count(),
            'info': Vulnerability.query.filter_by(severity='info').count()
        }
        
        # Get recent system logs
        recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(10).all()
        
        return render_template('index.html',
                             recent_scans=recent_scans,
                             total_scans=total_scans,
                             total_customers=total_customers,
                             total_vulnerabilities=total_vulnerabilities,
                             total_compliance_issues=total_compliance_issues,
                             vuln_counts=vuln_counts,
                             recent_logs=recent_logs)
    
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard data', 'error')
        # Provide default values to avoid template errors
        return render_template('index.html',
                             recent_scans=[],
                             total_scans=0,
                             total_customers=0,
                             total_vulnerabilities=0,
                             total_compliance_issues=0,
                             vuln_counts={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                             recent_logs=[])

@main_bp.route('/customers')
def customers():
    """Customers management page"""
    try:
        page = request.args.get('page', 1, type=int)
        customers = Customer.query.order_by(Customer.created_at.desc()).paginate(
            page=page, per_page=10, error_out=False
        )
        return render_template('customers.html', customers=customers)
    
    except Exception as e:
        logger.error(f"Error loading customers page: {str(e)}")
        flash('Error loading customers', 'error')
        return render_template('customers.html', customers=None)

@main_bp.route('/scans')
def scans():
    """Scans management page"""
    try:
        page = request.args.get('page', 1, type=int)
        status = request.args.get('status')
        customer_id = request.args.get('customer_id')
        
        query = Scan.query
        
        if status:
            query = query.filter_by(status=status)
        if customer_id:
            query = query.filter_by(customer_id=customer_id)
        
        scans = query.order_by(Scan.created_at.desc()).paginate(
            page=page, per_page=10, error_out=False
        )
        
        return render_template('scans.html', scans=scans)
    
    except Exception as e:
        logger.error(f"Error loading scans page: {str(e)}")
        flash('Error loading scans', 'error')
        return render_template('scans.html', scans=None)

@main_bp.route('/scans/<int:scan_id>')
def scan_detail(scan_id):
    """Scan detail page"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        customer = Customer.query.get(scan.customer_id)
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        ports = Port.query.filter_by(scan_id=scan_id).all()
        compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
        
        # Group vulnerabilities by severity
        vuln_by_severity = {
            'critical': [v for v in vulnerabilities if v.severity == 'critical'],
            'high': [v for v in vulnerabilities if v.severity == 'high'],
            'medium': [v for v in vulnerabilities if v.severity == 'medium'],
            'low': [v for v in vulnerabilities if v.severity == 'low'],
            'info': [v for v in vulnerabilities if v.severity == 'info']
        }
        
        return render_template('scan_detail.html',
                             scan=scan,
                             customer=customer,
                             vulnerabilities=vulnerabilities,
                             ports=ports,
                             compliance_issues=compliance_issues,
                             vuln_by_severity=vuln_by_severity)
    
    except Exception as e:
        logger.error(f"Error loading scan detail: {str(e)}")
        flash('Error loading scan details', 'error')
        return redirect(url_for('main.scans'))

@main_bp.route('/customers/<int:customer_id>')
def customer_detail(customer_id):
    """Customer detail page"""
    try:
        customer = Customer.query.get_or_404(customer_id)
        scans = Scan.query.filter_by(customer_id=customer_id).order_by(Scan.created_at.desc()).all()
        
        # Calculate statistics
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.status == 'completed'])
        running_scans = len([s for s in scans if s.status == 'running'])
        failed_scans = len([s for s in scans if s.status == 'failed'])
        
        return render_template('customer_detail.html',
                             customer=customer,
                             scans=scans,
                             total_scans=total_scans,
                             completed_scans=completed_scans,
                             running_scans=running_scans,
                             failed_scans=failed_scans)
    
    except Exception as e:
        logger.error(f"Error loading customer detail: {str(e)}")
        flash('Error loading customer details', 'error')
        return redirect(url_for('main.customers'))

@main_bp.route('/monitoring')
def monitoring():
    """System monitoring page"""
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
            logger.warning("psutil not available, using default system stats")
            system_stats = {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_percent': 0,
                'boot_time': 0
            }
        
        # Get recent system logs
        recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(50).all()
        
        # Get active scans
        active_scans = Scan.query.filter(Scan.status.in_(['pending', 'running'])).all()
        
        return render_template('monitoring.html',
                             system_stats=system_stats,
                             recent_logs=recent_logs,
                             active_scans=active_scans)
    
    except Exception as e:
        logger.error(f"Error loading monitoring page: {str(e)}")
        flash('Error loading monitoring data', 'error')
        # Provide default values to avoid template errors
        return render_template('monitoring.html',
                             system_stats={
                                 'cpu_percent': 0,
                                 'memory_percent': 0,
                                 'disk_percent': 0,
                                 'boot_time': 0
                             },
                             recent_logs=[],
                             active_scans=[])

@main_bp.route('/scan-types')
def scan_types():
    """Scan types management page"""
    return render_template('scan_types.html')

@main_bp.route('/reports')
def reports():
    """Reports page"""
    try:
        # Get completed scans for report generation
        completed_scans = Scan.query.filter_by(status='completed').order_by(Scan.completed_at.desc()).all()
        return render_template('reports.html', scans=completed_scans)
    
    except Exception as e:
        logger.error(f"Error loading reports page: {str(e)}")
        flash('Error loading reports', 'error')
        return render_template('reports.html', scans=[])

@main_bp.route('/settings')
def settings():
    """Settings page"""
    try:
        return render_template('settings.html')
    
    except Exception as e:
        logger.error(f"Error loading settings page: {str(e)}")
        flash('Error loading settings', 'error')
        return render_template('settings.html')

# SocketIO events
@main_bp.route('/socketio')
def socketio_test():
    """Test SocketIO connection"""
    return render_template('socketio_test.html')

# Health check endpoint
@main_bp.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'version': '1.0.0'
        })
    
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500