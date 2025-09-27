"""
Monitoring routes
Handles system monitoring and analytics
"""

from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models import Scan, Customer, Vulnerability, Port, ComplianceIssue, SystemLog, ScanTask
from app.modules.logger import get_logger
import psutil
import json
from datetime import datetime, timedelta

monitor_bp = Blueprint('monitor', __name__)
logger = get_logger(__name__)

@monitor_bp.route('/dashboard', methods=['GET'])
def get_dashboard_data():
    """Get dashboard monitoring data"""
    try:
        # System statistics
        system_stats = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'boot_time': psutil.boot_time(),
            'uptime': datetime.now().timestamp() - psutil.boot_time()
        }
        
        # Application statistics
        app_stats = {
            'total_scans': Scan.query.count(),
            'active_scans': Scan.query.filter(Scan.status.in_(['pending', 'running'])).count(),
            'completed_scans': Scan.query.filter_by(status='completed').count(),
            'failed_scans': Scan.query.filter_by(status='failed').count(),
            'total_customers': Customer.query.count(),
            'total_vulnerabilities': Vulnerability.query.count(),
            'total_compliance_issues': ComplianceIssue.query.count()
        }
        
        # Recent activity
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
        recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(20).all()
        
        # Active tasks
        active_tasks = ScanTask.query.filter(ScanTask.status.in_(['pending', 'running'])).all()
        
        # Vulnerability trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_vulns = Vulnerability.query.filter(Vulnerability.created_at >= thirty_days_ago).all()
        
        vuln_trends = {
            'critical': len([v for v in recent_vulns if v.severity == 'critical']),
            'high': len([v for v in recent_vulns if v.severity == 'high']),
            'medium': len([v for v in recent_vulns if v.severity == 'medium']),
            'low': len([v for v in recent_vulns if v.severity == 'low']),
            'info': len([v for v in recent_vulns if v.severity == 'info'])
        }
        
        # Scan trends (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_scans_trend = Scan.query.filter(Scan.created_at >= seven_days_ago).all()
        
        scan_trends = {
            'total': len(recent_scans_trend),
            'completed': len([s for s in recent_scans_trend if s.status == 'completed']),
            'failed': len([s for s in recent_scans_trend if s.status == 'failed']),
            'running': len([s for s in recent_scans_trend if s.status == 'running'])
        }
        
        dashboard_data = {
            'system_stats': system_stats,
            'app_stats': app_stats,
            'recent_scans': [scan.to_dict() for scan in recent_scans],
            'recent_logs': [log.to_dict() for log in recent_logs],
            'active_tasks': [task.to_dict() for task in active_tasks],
            'vuln_trends': vuln_trends,
            'scan_trends': scan_trends,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(dashboard_data)
    
    except Exception as e:
        logger.error(f"Error getting dashboard data: {str(e)}")
        return jsonify({'error': 'Failed to get dashboard data'}), 500

@monitor_bp.route('/system', methods=['GET'])
def get_system_info():
    """Get detailed system information"""
    try:
        # CPU information
        cpu_info = {
            'count': psutil.cpu_count(),
            'percent': psutil.cpu_percent(interval=1),
            'per_cpu': psutil.cpu_percent(interval=1, percpu=True),
            'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
        }
        
        # Memory information
        memory = psutil.virtual_memory()
        memory_info = {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used,
            'free': memory.free
        }
        
        # Disk information
        disk = psutil.disk_usage('/')
        disk_info = {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': (disk.used / disk.total) * 100
        }
        
        # Network information
        network = psutil.net_io_counters()
        network_info = {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv
        }
        
        # Process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        
        system_info = {
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_info,
            'network': network_info,
            'processes': processes[:20],  # Top 20 processes
            'boot_time': psutil.boot_time(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(system_info)
    
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return jsonify({'error': 'Failed to get system info'}), 500

@monitor_bp.route('/logs', methods=['GET'])
def get_system_logs():
    """Get system logs with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        level = request.args.get('level')
        component = request.args.get('component')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = SystemLog.query
        
        # Apply filters
        if level:
            query = query.filter_by(level=level)
        if component:
            query = query.filter_by(component=component)
        if start_date:
            start_dt = datetime.fromisoformat(start_date)
            query = query.filter(SystemLog.created_at >= start_dt)
        if end_date:
            end_dt = datetime.fromisoformat(end_date)
            query = query.filter(SystemLog.created_at <= end_dt)
        
        # Paginate results
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
        logger.error(f"Error getting system logs: {str(e)}")
        return jsonify({'error': 'Failed to get system logs'}), 500

@monitor_bp.route('/analytics/vulnerabilities', methods=['GET'])
def get_vulnerability_analytics():
    """Get vulnerability analytics"""
    try:
        # Time range
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get vulnerabilities in time range
        vulnerabilities = Vulnerability.query.filter(Vulnerability.created_at >= start_date).all()
        
        # Group by severity
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low']),
            'info': len([v for v in vulnerabilities if v.severity == 'info'])
        }
        
        # Group by status
        status_counts = {
            'open': len([v for v in vulnerabilities if v.status == 'open']),
            'in_progress': len([v for v in vulnerabilities if v.status == 'in_progress']),
            'resolved': len([v for v in vulnerabilities if v.status == 'resolved']),
            'false_positive': len([v for v in vulnerabilities if v.status == 'false_positive'])
        }
        
        # Top CVE IDs
        cve_counts = {}
        for vuln in vulnerabilities:
            if vuln.cve_id:
                cve_counts[vuln.cve_id] = cve_counts.get(vuln.cve_id, 0) + 1
        
        top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Daily trends
        daily_trends = {}
        for vuln in vulnerabilities:
            date_str = vuln.created_at.date().isoformat()
            daily_trends[date_str] = daily_trends.get(date_str, 0) + 1
        
        analytics = {
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'top_cves': top_cves,
            'daily_trends': daily_trends,
            'total_vulnerabilities': len(vulnerabilities),
            'time_range_days': days
        }
        
        return jsonify(analytics)
    
    except Exception as e:
        logger.error(f"Error getting vulnerability analytics: {str(e)}")
        return jsonify({'error': 'Failed to get vulnerability analytics'}), 500

@monitor_bp.route('/analytics/scans', methods=['GET'])
def get_scan_analytics():
    """Get scan analytics"""
    try:
        # Time range
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get scans in time range
        scans = Scan.query.filter(Scan.created_at >= start_date).all()
        
        # Group by status
        status_counts = {
            'completed': len([s for s in scans if s.status == 'completed']),
            'running': len([s for s in scans if s.status == 'running']),
            'failed': len([s for s in scans if s.status == 'failed']),
            'cancelled': len([s for s in scans if s.status == 'cancelled']),
            'pending': len([s for s in scans if s.status == 'pending'])
        }
        
        # Group by scan type
        type_counts = {}
        for scan in scans:
            type_counts[scan.scan_type] = type_counts.get(scan.scan_type, 0) + 1
        
        # Daily trends
        daily_trends = {}
        for scan in scans:
            date_str = scan.created_at.date().isoformat()
            daily_trends[date_str] = daily_trends.get(date_str, 0) + 1
        
        # Average scan duration
        completed_scans = [s for s in scans if s.status == 'completed' and s.started_at and s.completed_at]
        avg_duration = 0
        if completed_scans:
            total_duration = sum((s.completed_at - s.started_at).total_seconds() for s in completed_scans)
            avg_duration = total_duration / len(completed_scans)
        
        # Top customers by scan count
        customer_scan_counts = {}
        for scan in scans:
            customer_id = scan.customer_id
            customer_scan_counts[customer_id] = customer_scan_counts.get(customer_id, 0) + 1
        
        top_customers = sorted(customer_scan_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        analytics = {
            'status_counts': status_counts,
            'type_counts': type_counts,
            'daily_trends': daily_trends,
            'average_duration_seconds': avg_duration,
            'top_customers': top_customers,
            'total_scans': len(scans),
            'time_range_days': days
        }
        
        return jsonify(analytics)
    
    except Exception as e:
        logger.error(f"Error getting scan analytics: {str(e)}")
        return jsonify({'error': 'Failed to get scan analytics'}), 500

@monitor_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get system alerts and warnings"""
    try:
        alerts = []
        
        # Check for high CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 80:
            alerts.append({
                'type': 'warning',
                'component': 'system',
                'message': f'High CPU usage: {cpu_percent}%',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Check for high memory usage
        memory_percent = psutil.virtual_memory().percent
        if memory_percent > 85:
            alerts.append({
                'type': 'warning',
                'component': 'system',
                'message': f'High memory usage: {memory_percent}%',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Check for high disk usage
        disk_percent = psutil.disk_usage('/').percent
        if disk_percent > 90:
            alerts.append({
                'type': 'critical',
                'component': 'system',
                'message': f'High disk usage: {disk_percent}%',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Check for failed scans
        failed_scans = Scan.query.filter_by(status='failed').filter(
            Scan.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        if failed_scans > 5:
            alerts.append({
                'type': 'warning',
                'component': 'scanner',
                'message': f'{failed_scans} scans failed in the last 24 hours',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Check for critical vulnerabilities
        critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
        if critical_vulns > 0:
            alerts.append({
                'type': 'critical',
                'component': 'security',
                'message': f'{critical_vulns} critical vulnerabilities found',
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return jsonify({
            'alerts': alerts,
            'total_alerts': len(alerts),
            'critical_alerts': len([a for a in alerts if a['type'] == 'critical']),
            'warning_alerts': len([a for a in alerts if a['type'] == 'warning'])
        })
    
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        return jsonify({'error': 'Failed to get alerts'}), 500

@monitor_bp.route('/health', methods=['GET'])
def health_check():
    """System health check"""
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {}
        }
        
        # Database check
        try:
            db.session.execute('SELECT 1')
            health_status['checks']['database'] = 'healthy'
        except Exception as e:
            health_status['checks']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # Redis check (if using Redis)
        try:
            # This would need to be implemented based on your Redis setup
            health_status['checks']['redis'] = 'healthy'
        except Exception as e:
            health_status['checks']['redis'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # System resources check
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        if cpu_percent > 90:
            health_status['checks']['cpu'] = f'warning: {cpu_percent}%'
        else:
            health_status['checks']['cpu'] = 'healthy'
        
        if memory_percent > 90:
            health_status['checks']['memory'] = f'warning: {memory_percent}%'
        else:
            health_status['checks']['memory'] = 'healthy'
        
        if disk_percent > 95:
            health_status['checks']['disk'] = f'critical: {disk_percent}%'
            health_status['status'] = 'unhealthy'
        else:
            health_status['checks']['disk'] = 'healthy'
        
        return jsonify(health_status)
    
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
