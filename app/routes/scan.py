"""
Scan management routes
Handles scan creation, execution, and monitoring
"""

from flask import Blueprint, request, jsonify, current_app
from flask_socketio import emit
from app import db
from app.tasks.scan_tasks import celery
from app.models import Scan, Customer, ScanTask, SystemLog
from app.modules.logger import get_logger
from app.tasks.scan_tasks import run_nmap_scan, run_cve_lookup, run_osint_scan, run_compliance_check
import json

scan_bp = Blueprint('scan', __name__)
logger = get_logger(__name__)

@scan_bp.route('/create', methods=['POST'])
def create_scan():
    """Create a new scan"""
    try:
        data = request.get_json()
        
        if not data or not data.get('customer_id') or not data.get('target'):
            return jsonify({'error': 'Customer ID and target are required'}), 400
        
        # Validate customer exists
        customer = Customer.query.get(data['customer_id'])
        if not customer:
            return jsonify({'error': 'Customer not found'}), 404
        
        # Create scan
        scan = Scan(
            customer_id=data['customer_id'],
            name=data.get('name', f"Scan of {data['target']}"),
            target=data['target'],
            scan_type=data.get('scan_type', 'full_scan'),
            nmap_options=json.dumps(data.get('nmap_options', {})),
            enable_osint=data.get('enable_osint', False),
            enable_cve_lookup=data.get('enable_cve_lookup', True),
            enable_compliance_check=data.get('enable_compliance_check', True)
        )
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info(f"Created scan {scan.id} for target {scan.target}")
        
        # Log scan creation
        log_entry = SystemLog(
            level='info',
            component='scan_manager',
            message=f"Scan {scan.id} created for target {scan.target}",
            details=json.dumps(scan.to_dict())
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify(scan.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating scan: {str(e)}")
        return jsonify({'error': 'Failed to create scan'}), 500

@scan_bp.route('/<int:scan_id>/start', methods=['POST'])
def start_scan(scan_id):
    """Start a scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        if scan.status != 'pending':
            return jsonify({'error': f'Scan is already {scan.status}'}), 400
        
        # Update scan status
        scan.status = 'running'
        scan.started_at = db.func.now()
        db.session.commit()
        
        # Start background tasks
        task_ids = []
        
        # Start nmap scan
        nmap_task = run_nmap_scan.delay(scan_id)
        task_ids.append(nmap_task.id)
        
        # Create task tracking records
        nmap_task_record = ScanTask(
            task_id=nmap_task.id,
            scan_id=scan_id,
            task_type='nmap_scan',
            status='pending'
        )
        db.session.add(nmap_task_record)
        
        # Start CVE lookup if enabled
        if scan.enable_cve_lookup:
            cve_task = run_cve_lookup.delay(scan_id)
            task_ids.append(cve_task.id)
            
            cve_task_record = ScanTask(
                task_id=cve_task.id,
                scan_id=scan_id,
                task_type='cve_lookup',
                status='pending'
            )
            db.session.add(cve_task_record)
        
        # Start OSINT scan if enabled
        if scan.enable_osint:
            osint_task = run_osint_scan.delay(scan_id)
            task_ids.append(osint_task.id)
            
            osint_task_record = ScanTask(
                task_id=osint_task.id,
                scan_id=scan_id,
                task_type='osint_scan',
                status='pending'
            )
            db.session.add(osint_task_record)
        
        # Start compliance check if enabled
        if scan.enable_compliance_check:
            compliance_task = run_compliance_check.delay(scan_id)
            task_ids.append(compliance_task.id)
            
            compliance_task_record = ScanTask(
                task_id=compliance_task.id,
                scan_id=scan_id,
                task_type='compliance_check',
                status='pending'
            )
            db.session.add(compliance_task_record)
        
        db.session.commit()
        
        # Emit scan start event
        emit('scan_started', {
            'scan_id': scan_id,
            'target': scan.target,
            'task_ids': task_ids
        }, room=f'scan_{scan_id}')
        
        logger.info(f"Started scan {scan_id} with {len(task_ids)} tasks")
        
        # Log scan start
        log_entry = SystemLog(
            level='info',
            component='scan_manager',
            message=f"Scan {scan_id} started with {len(task_ids)} tasks",
            details=json.dumps({'task_ids': task_ids})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Scan started successfully',
            'scan_id': scan_id,
            'task_ids': task_ids
        })
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error starting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to start scan'}), 500

@scan_bp.route('/<int:scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        if scan.status not in ['running', 'pending']:
            return jsonify({'error': f'Cannot stop scan with status {scan.status}'}), 400
        
        # Get active tasks
        active_tasks = ScanTask.query.filter_by(scan_id=scan_id, status='running').all()
        
        # Revoke Celery tasks
        for task in active_tasks:
            celery.control.revoke(task.task_id, terminate=True)
            task.status = 'cancelled'
            task.completed_at = db.func.now()
        
        # Update scan status
        scan.status = 'cancelled'
        scan.completed_at = db.func.now()
        db.session.commit()
        
        # Emit scan stop event
        emit('scan_stopped', {
            'scan_id': scan_id,
            'target': scan.target
        }, room=f'scan_{scan_id}')
        
        logger.info(f"Stopped scan {scan_id}")
        
        # Log scan stop
        log_entry = SystemLog(
            level='info',
            component='scan_manager',
            message=f"Scan {scan_id} stopped by user",
            details=json.dumps({'scan_id': scan_id})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'message': 'Scan stopped successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error stopping scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to stop scan'}), 500

@scan_bp.route('/<int:scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and progress"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        tasks = ScanTask.query.filter_by(scan_id=scan_id).all()
        
        # Calculate overall progress
        if tasks:
            total_tasks = len(tasks)
            completed_tasks = len([t for t in tasks if t.status == 'completed'])
            failed_tasks = len([t for t in tasks if t.status == 'failed'])
            progress = int((completed_tasks / total_tasks) * 100)
        else:
            progress = 0
        
        # Update scan progress
        scan.progress = progress
        db.session.commit()
        
        status_data = {
            'scan_id': scan_id,
            'status': scan.status,
            'progress': progress,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'tasks': [task.to_dict() for task in tasks]
        }
        
        return jsonify(status_data)
    
    except Exception as e:
        logger.error(f"Error getting scan status {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get scan status'}), 500

@scan_bp.route('/<int:scan_id>/tasks', methods=['GET'])
def get_scan_tasks(scan_id):
    """Get tasks for a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        tasks = ScanTask.query.filter_by(scan_id=scan_id).all()
        
        return jsonify([task.to_dict() for task in tasks])
    
    except Exception as e:
        logger.error(f"Error getting tasks for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get scan tasks'}), 500

@scan_bp.route('/<int:scan_id>/update_progress', methods=['POST'])
def update_scan_progress(scan_id):
    """Update scan progress (called by background tasks)"""
    try:
        data = request.get_json()
        task_id = data.get('task_id')
        progress = data.get('progress', 0)
        status = data.get('status', 'running')
        result = data.get('result')
        error = data.get('error')
        
        # Update task
        task = ScanTask.query.filter_by(task_id=task_id).first()
        if task:
            task.progress = progress
            task.status = status
            if result:
                task.result = json.dumps(result)
            if error:
                task.error_message = error
            if status in ['completed', 'failed']:
                task.completed_at = db.func.now()
            
            db.session.commit()
        
        # Update scan progress
        scan = Scan.query.get(scan_id)
        if scan:
            # Calculate overall progress
            tasks = ScanTask.query.filter_by(scan_id=scan_id).all()
            if tasks:
                total_tasks = len(tasks)
                completed_tasks = len([t for t in tasks if t.status == 'completed'])
                scan.progress = int((completed_tasks / total_tasks) * 100)
                
                # Check if all tasks are complete
                if completed_tasks == total_tasks:
                    scan.status = 'completed'
                    scan.completed_at = db.func.now()
                elif any(t.status == 'failed' for t in tasks):
                    scan.status = 'failed'
                    scan.completed_at = db.func.now()
            
            db.session.commit()
            
            # Emit progress update
            emit('scan_progress', {
                'scan_id': scan_id,
                'progress': scan.progress,
                'status': scan.status,
                'task_id': task_id,
                'task_status': status
            }, room=f'scan_{scan_id}')
            
            # Emit completion notification
            if scan.status == 'completed':
                emit('scan_complete', {
                    'scan_id': scan_id,
                    'target': scan.target,
                    'progress': scan.progress
                }, room=f'scan_{scan_id}')
                
                # Also emit to all clients for notifications
                emit('scan_complete_notification', {
                    'scan_id': scan_id,
                    'target': scan.target,
                    'scan_name': scan.name
                })
        
        return jsonify({'message': 'Progress updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating scan progress: {str(e)}")
        return jsonify({'error': 'Failed to update progress'}), 500

@scan_bp.route('/<int:scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan and all associated data"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # Cancel any running tasks
        if scan.status in ['running', 'pending']:
            active_tasks = ScanTask.query.filter_by(scan_id=scan_id, status='running').all()
            for task in active_tasks:
                celery.control.revoke(task.task_id, terminate=True)
        
        # Delete scan (cascade will handle related records)
        db.session.delete(scan)
        db.session.commit()
        
        logger.info(f"Deleted scan {scan_id}")
        
        # Log scan deletion
        log_entry = SystemLog(
            level='info',
            component='scan_manager',
            message=f"Scan {scan_id} deleted",
            details=json.dumps({'scan_id': scan_id})
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'message': 'Scan deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete scan'}), 500
