"""
Celery tasks for vulnerability scanning
Handles background execution of scans and lookups
"""

from celery import current_task, Celery
from app import db
import os

# Create celery instance
celery = Celery(
    'vuln_scanner',
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
)
from app.models import Scan, Port, Vulnerability, ScanTask, SystemLog
from app.modules.nmap_scanner import NmapScanner
from app.modules.searchsploit_scanner import SearchsploitScanner
from app.modules.cve_lookup import CVELookup
from app.modules.osint_scanner import OSINTScanner
from app.modules.compliance_checker import ComplianceChecker
from app.modules.logger import get_logger
import json

logger = get_logger(__name__)

@celery.task(bind=True)
def run_nmap_scan(self, scan_id):
    """Run Nmap scan for a target"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting nmap scan'})
        
        # Get scan
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'running'
            task_record.started_at = db.func.now()
            db.session.commit()
        
        # Initialize scanner
        nmap_scanner = NmapScanner()
        
        # Parse nmap options
        nmap_options = json.loads(scan.nmap_options) if scan.nmap_options else {}
        
        # Run scan
        self.update_state(state='PROGRESS', meta={'progress': 25, 'status': 'Running nmap scan'})
        results = nmap_scanner.scan_target(scan.target, nmap_options)
        
        # Save results
        self.update_state(state='PROGRESS', meta={'progress': 75, 'status': 'Saving nmap results'})
        nmap_scanner.save_scan_results(scan_id, results)
        
        # Update task record
        if task_record:
            task_record.status = 'completed'
            task_record.progress = 100
            task_record.result = json.dumps(results)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log completion
        log_entry = SystemLog(
            level='info',
            component='nmap_scanner',
            message=f"Nmap scan completed for scan {scan_id}",
            details=json.dumps({'scan_id': scan_id, 'target': scan.target})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Emit progress update
        from app.routes.main import emit_scan_update
        emit_scan_update(scan_id, {
            'task_type': 'nmap_scan',
            'progress': 100,
            'status': 'completed',
            'results': results
        })
        
        logger.info(f"Nmap scan completed for scan {scan_id}")
        return {'status': 'completed', 'results': results}
    
    except Exception as e:
        logger.error(f"Nmap scan failed for scan {scan_id}: {str(e)}")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'failed'
            task_record.error_message = str(e)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log error
        log_entry = SystemLog(
            level='error',
            component='nmap_scanner',
            message=f"Nmap scan failed for scan {scan_id}: {str(e)}",
            details=json.dumps({'scan_id': scan_id, 'error': str(e)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        raise

@celery.task(bind=True)
def run_cve_lookup(self, scan_id):
    """Run CVE lookup for discovered services"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting CVE lookup'})
        
        # Get scan
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'running'
            task_record.started_at = db.func.now()
            db.session.commit()
        
        # Get open ports
        ports = Port.query.filter_by(scan_id=scan_id, state='open').all()
        
        if not ports:
            logger.info(f"No open ports found for CVE lookup in scan {scan_id}")
            return {'status': 'completed', 'message': 'No open ports found'}
        
        # Initialize CVE lookup
        cve_lookup = CVELookup()
        
        cve_results = []
        
        # Look up CVEs for each service
        for i, port in enumerate(ports):
            progress = int((i / len(ports)) * 80) + 10  # 10-90%
            self.update_state(state='PROGRESS', meta={
                'progress': progress, 
                'status': f'Looking up CVEs for {port.service} on port {port.port_number}'
            })
            
            if port.service and port.service != 'unknown':
                # Search for CVEs by service name
                cves = cve_lookup.search_cves_by_service(port.service, port.version)
                
                for cve_data in cves:
                    # Save CVE results
                    cve_lookup.save_cve_results(scan_id, port.id, cve_data)
                    cve_results.append(cve_data)
        
        # Update task record
        if task_record:
            task_record.status = 'completed'
            task_record.progress = 100
            task_record.result = json.dumps({'cve_count': len(cve_results)})
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log completion
        log_entry = SystemLog(
            level='info',
            component='cve_lookup',
            message=f"CVE lookup completed for scan {scan_id}: {len(cve_results)} CVEs found",
            details=json.dumps({'scan_id': scan_id, 'cve_count': len(cve_results)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Emit progress update
        from app.routes.main import emit_scan_update
        emit_scan_update(scan_id, {
            'task_type': 'cve_lookup',
            'progress': 100,
            'status': 'completed',
            'cve_count': len(cve_results)
        })
        
        logger.info(f"CVE lookup completed for scan {scan_id}: {len(cve_results)} CVEs found")
        return {'status': 'completed', 'cve_count': len(cve_results)}
    
    except Exception as e:
        logger.error(f"CVE lookup failed for scan {scan_id}: {str(e)}")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'failed'
            task_record.error_message = str(e)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log error
        log_entry = SystemLog(
            level='error',
            component='cve_lookup',
            message=f"CVE lookup failed for scan {scan_id}: {str(e)}",
            details=json.dumps({'scan_id': scan_id, 'error': str(e)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        raise

@celery.task(bind=True)
def run_osint_scan(self, scan_id):
    """Run OSINT data collection"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting OSINT collection'})
        
        # Get scan
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'running'
            task_record.started_at = db.func.now()
            db.session.commit()
        
        # Initialize OSINT scanner
        osint_scanner = OSINTScanner()
        
        # Collect OSINT data
        self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'Collecting OSINT data'})
        osint_data = osint_scanner.collect_osint_data(scan.target, scan_id)
        
        # Update task record
        if task_record:
            task_record.status = 'completed'
            task_record.progress = 100
            task_record.result = json.dumps(osint_data)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log completion
        log_entry = SystemLog(
            level='info',
            component='osint_scanner',
            message=f"OSINT collection completed for scan {scan_id}",
            details=json.dumps({'scan_id': scan_id, 'target': scan.target})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Emit progress update
        from app.routes.main import emit_scan_update
        emit_scan_update(scan_id, {
            'task_type': 'osint_scan',
            'progress': 100,
            'status': 'completed',
            'osint_data': osint_data
        })
        
        logger.info(f"OSINT collection completed for scan {scan_id}")
        return {'status': 'completed', 'osint_data': osint_data}
    
    except Exception as e:
        logger.error(f"OSINT collection failed for scan {scan_id}: {str(e)}")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'failed'
            task_record.error_message = str(e)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log error
        log_entry = SystemLog(
            level='error',
            component='osint_scanner',
            message=f"OSINT collection failed for scan {scan_id}: {str(e)}",
            details=json.dumps({'scan_id': scan_id, 'error': str(e)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        raise

@celery.task(bind=True)
def run_compliance_check(self, scan_id):
    """Run NIST compliance check"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting compliance check'})
        
        # Get scan
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'running'
            task_record.started_at = db.func.now()
            db.session.commit()
        
        # Initialize compliance checker
        compliance_checker = ComplianceChecker()
        
        # Run compliance check
        self.update_state(state='PROGRESS', meta={'progress': 50, 'status': 'Running compliance check'})
        compliance_issues = compliance_checker.check_compliance(scan_id)
        
        # Update task record
        if task_record:
            task_record.status = 'completed'
            task_record.progress = 100
            task_record.result = json.dumps({'compliance_issues': len(compliance_issues)})
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log completion
        log_entry = SystemLog(
            level='info',
            component='compliance_checker',
            message=f"Compliance check completed for scan {scan_id}: {len(compliance_issues)} issues found",
            details=json.dumps({'scan_id': scan_id, 'compliance_issues': len(compliance_issues)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Emit progress update
        from app.routes.main import emit_scan_update
        emit_scan_update(scan_id, {
            'task_type': 'compliance_check',
            'progress': 100,
            'status': 'completed',
            'compliance_issues': len(compliance_issues)
        })
        
        logger.info(f"Compliance check completed for scan {scan_id}: {len(compliance_issues)} issues found")
        return {'status': 'completed', 'compliance_issues': len(compliance_issues)}
    
    except Exception as e:
        logger.error(f"Compliance check failed for scan {scan_id}: {str(e)}")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'failed'
            task_record.error_message = str(e)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log error
        log_entry = SystemLog(
            level='error',
            component='compliance_checker',
            message=f"Compliance check failed for scan {scan_id}: {str(e)}",
            details=json.dumps({'scan_id': scan_id, 'error': str(e)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        raise

@celery.task(bind=True)
def run_searchsploit_scan(self, scan_id):
    """Run Searchsploit scan for discovered services"""
    try:
        # Update task status
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting searchsploit scan'})
        
        # Get scan
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'running'
            task_record.started_at = db.func.now()
            db.session.commit()
        
        # Get open ports
        ports = Port.query.filter_by(scan_id=scan_id, state='open').all()
        
        if not ports:
            logger.info(f"No open ports found for searchsploit scan in scan {scan_id}")
            return {'status': 'completed', 'message': 'No open ports found'}
        
        # Initialize searchsploit scanner
        searchsploit_scanner = SearchsploitScanner()
        
        exploit_results = []
        
        # Search for exploits for each service
        for i, port in enumerate(ports):
            progress = int((i / len(ports)) * 80) + 10  # 10-90%
            self.update_state(state='PROGRESS', meta={
                'progress': progress, 
                'status': f'Searching exploits for {port.service} on port {port.port_number}'
            })
            
            if port.service and port.service != 'unknown':
                # Search for exploits
                exploits = searchsploit_scanner.search_exploits(port.service, port.version)
                
                if exploits:
                    # Save exploit results
                    searchsploit_scanner.save_exploit_results(scan_id, port.id, exploits)
                    exploit_results.extend(exploits)
        
        # Update task record
        if task_record:
            task_record.status = 'completed'
            task_record.progress = 100
            task_record.result = json.dumps({'exploit_count': len(exploit_results)})
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log completion
        log_entry = SystemLog(
            level='info',
            component='searchsploit_scanner',
            message=f"Searchsploit scan completed for scan {scan_id}: {len(exploit_results)} exploits found",
            details=json.dumps({'scan_id': scan_id, 'exploit_count': len(exploit_results)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Emit progress update
        from app.routes.main import emit_scan_update
        emit_scan_update(scan_id, {
            'task_type': 'searchsploit_scan',
            'progress': 100,
            'status': 'completed',
            'exploit_count': len(exploit_results)
        })
        
        logger.info(f"Searchsploit scan completed for scan {scan_id}: {len(exploit_results)} exploits found")
        return {'status': 'completed', 'exploit_count': len(exploit_results)}
    
    except Exception as e:
        logger.error(f"Searchsploit scan failed for scan {scan_id}: {str(e)}")
        
        # Update task record
        task_record = ScanTask.query.filter_by(task_id=self.request.id).first()
        if task_record:
            task_record.status = 'failed'
            task_record.error_message = str(e)
            task_record.completed_at = db.func.now()
            db.session.commit()
        
        # Log error
        log_entry = SystemLog(
            level='error',
            component='searchsploit_scanner',
            message=f"Searchsploit scan failed for scan {scan_id}: {str(e)}",
            details=json.dumps({'scan_id': scan_id, 'error': str(e)})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        raise
