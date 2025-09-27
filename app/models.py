"""
Database models for the vulnerability scanner application
"""

from datetime import datetime
from app import db
from sqlalchemy.dialects.postgresql import JSON
import json

class Customer(db.Model):
    """Customer/Client information"""
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    organization = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', backref='customer', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'organization': self.organization,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Scan(db.Model):
    """Scan session information"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    target = db.Column(db.String(255), nullable=False)  # IP address or hostname
    scan_type = db.Column(db.String(50), nullable=False)  # 'port_scan', 'vuln_scan', 'full_scan'
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)  # 0-100
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Scan configuration
    nmap_options = db.Column(db.Text)  # JSON string of nmap options
    enable_osint = db.Column(db.Boolean, default=False)
    enable_cve_lookup = db.Column(db.Boolean, default=True)
    enable_compliance_check = db.Column(db.Boolean, default=True)
    
    # Relationships
    ports = db.relationship('Port', backref='scan', lazy=True, cascade='all, delete-orphan')
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    compliance_issues = db.relationship('ComplianceIssue', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'customer_id': self.customer_id,
            'name': self.name,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'progress': self.progress,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'nmap_options': json.loads(self.nmap_options) if self.nmap_options else {},
            'enable_osint': self.enable_osint,
            'enable_cve_lookup': self.enable_cve_lookup,
            'enable_compliance_check': self.enable_compliance_check
        }

class Port(db.Model):
    """Open ports discovered during scans"""
    __tablename__ = 'ports'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # tcp, udp
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered
    service = db.Column(db.String(100))
    version = db.Column(db.String(255))
    banner = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'banner': self.banner,
            'created_at': self.created_at.isoformat()
        }

class Vulnerability(db.Model):
    """Vulnerabilities discovered during scans"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'), nullable=True)
    cve_id = db.Column(db.String(20), nullable=True)  # CVE-YYYY-NNNN
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(100))
    exploit_available = db.Column(db.Boolean, default=False)
    exploit_reference = db.Column(db.String(500))
    remediation = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, false_positive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'port_id': self.port_id,
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'exploit_available': self.exploit_available,
            'exploit_reference': self.exploit_reference,
            'remediation': self.remediation,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class ComplianceIssue(db.Model):
    """NIST framework compliance issues"""
    __tablename__ = 'compliance_issues'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    nist_control = db.Column(db.String(50), nullable=False)  # e.g., PR.AC-1
    control_title = db.Column(db.String(255), nullable=False)
    issue_description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    recommendation = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'nist_control': self.nist_control,
            'control_title': self.control_title,
            'issue_description': self.issue_description,
            'severity': self.severity,
            'recommendation': self.recommendation,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class ScanTask(db.Model):
    """Background task tracking"""
    __tablename__ = 'scan_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(255), unique=True, nullable=False)  # Celery task ID
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    task_type = db.Column(db.String(50), nullable=False)  # nmap_scan, cve_lookup, osint, etc.
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)
    result = db.Column(db.Text)  # JSON string of task result
    error_message = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'scan_id': self.scan_id,
            'task_type': self.task_type,
            'status': self.status,
            'progress': self.progress,
            'result': json.loads(self.result) if self.result else None,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat()
        }

class SystemLog(db.Model):
    """System logs and monitoring data"""
    __tablename__ = 'system_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)  # info, warning, error, critical
    component = db.Column(db.String(50), nullable=False)  # scanner, api, web, celery, etc.
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # JSON string of additional details
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'level': self.level,
            'component': self.component,
            'message': self.message,
            'details': json.loads(self.details) if self.details else None,
            'created_at': self.created_at.isoformat()
        }
