"""
Tests for database models
"""

import pytest
from datetime import datetime
from app import create_app, db
from app.models import Customer, Scan, Vulnerability, Port, ComplianceIssue

@pytest.fixture
def app():
    """Create test application"""
    app, _ = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def sample_customer(app):
    """Create sample customer for testing"""
    with app.app_context():
        customer = Customer(
            name='Test Customer',
            email='test@example.com',
            organization='Test Org'
        )
        db.session.add(customer)
        db.session.commit()
        db.session.refresh(customer)  # Refresh to ensure object is attached
        return customer

@pytest.fixture
def sample_scan(app, sample_customer):
    """Create sample scan for testing"""
    with app.app_context():
        scan = Scan(
            customer_id=sample_customer.id,
            name='Test Scan',
            target='192.168.1.1',
            scan_type='full_scan',
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()
        db.session.refresh(scan)  # Refresh to ensure object is attached
        return scan

def test_customer_creation(app):
    """Test customer creation"""
    with app.app_context():
        customer = Customer(
            name='Test Customer',
            email='test@example.com',
            organization='Test Org'
        )
        db.session.add(customer)
        db.session.commit()
        
        assert customer.id is not None
        assert customer.name == 'Test Customer'
        assert customer.email == 'test@example.com'
        assert customer.organization == 'Test Org'

def test_customer_to_dict(app, sample_customer):
    """Test customer to_dict method"""
    with app.app_context():
        customer_dict = sample_customer.to_dict()
        
        assert 'id' in customer_dict
        assert 'name' in customer_dict
        assert 'email' in customer_dict
        assert 'organization' in customer_dict
        assert 'created_at' in customer_dict
        assert 'updated_at' in customer_dict

def test_scan_creation(app, sample_customer):
    """Test scan creation"""
    with app.app_context():
        scan = Scan(
            customer_id=sample_customer.id,
            name='Test Scan',
            target='192.168.1.1',
            scan_type='full_scan',
            status='pending'
        )
        db.session.add(scan)
        db.session.commit()
        
        assert scan.id is not None
        assert scan.customer_id == sample_customer.id
        assert scan.name == 'Test Scan'
        assert scan.target == '192.168.1.1'
        assert scan.scan_type == 'full_scan'
        assert scan.status == 'pending'

def test_scan_to_dict(app, sample_scan):
    """Test scan to_dict method"""
    with app.app_context():
        scan_dict = sample_scan.to_dict()
        
        assert 'id' in scan_dict
        assert 'customer_id' in scan_dict
        assert 'name' in scan_dict
        assert 'target' in scan_dict
        assert 'scan_type' in scan_dict
        assert 'status' in scan_dict
        assert 'progress' in scan_dict

def test_vulnerability_creation(app, sample_scan):
    """Test vulnerability creation"""
    with app.app_context():
        vulnerability = Vulnerability(
            scan_id=sample_scan.id,
            cve_id='CVE-2021-1234',
            title='Test Vulnerability',
            description='A test vulnerability',
            severity='high',
            cvss_score=7.5,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        )
        db.session.add(vulnerability)
        db.session.commit()
        
        assert vulnerability.id is not None
        assert vulnerability.scan_id == sample_scan.id
        assert vulnerability.cve_id == 'CVE-2021-1234'
        assert vulnerability.title == 'Test Vulnerability'
        assert vulnerability.severity == 'high'
        assert vulnerability.cvss_score == 7.5

def test_port_creation(app, sample_scan):
    """Test port creation"""
    with app.app_context():
        port = Port(
            scan_id=sample_scan.id,
            port_number=80,
            protocol='tcp',
            state='open',
            service='http',
            version='Apache/2.4.41'
        )
        db.session.add(port)
        db.session.commit()
        
        assert port.id is not None
        assert port.scan_id == sample_scan.id
        assert port.port_number == 80
        assert port.protocol == 'tcp'
        assert port.state == 'open'
        assert port.service == 'http'

def test_compliance_issue_creation(app, sample_scan):
    """Test compliance issue creation"""
    with app.app_context():
        compliance_issue = ComplianceIssue(
            scan_id=sample_scan.id,
            nist_control='PR.AC-1',
            control_title='Access Control',
            issue_description='Weak authentication controls',
            severity='high',
            recommendation='Implement multi-factor authentication'
        )
        db.session.add(compliance_issue)
        db.session.commit()
        
        assert compliance_issue.id is not None
        assert compliance_issue.scan_id == sample_scan.id
        assert compliance_issue.nist_control == 'PR.AC-1'
        assert compliance_issue.control_title == 'Access Control'
        assert compliance_issue.severity == 'high'

def test_relationships(app, sample_customer, sample_scan):
    """Test model relationships"""
    with app.app_context():
        # Reload objects within the app context to avoid DetachedInstanceError
        customer = Customer.query.get(sample_customer.id)
        scan = Scan.query.get(sample_scan.id)
        
        # Test customer -> scans relationship
        assert len(customer.scans) == 1
        assert customer.scans[0].id == scan.id
        
        # Test scan -> customer relationship
        assert scan.customer.id == customer.id
        assert scan.customer.name == customer.name

def test_cascade_delete(app, sample_customer, sample_scan):
    """Test cascade delete functionality"""
    with app.app_context():
        # Reload objects within the app context
        customer = Customer.query.get(sample_customer.id)
        scan = Scan.query.get(sample_scan.id)
        
        # Create related records
        vulnerability = Vulnerability(
            scan_id=scan.id,
            title='Test Vulnerability',
            severity='high'
        )
        port = Port(
            scan_id=scan.id,
            port_number=80,
            protocol='tcp',
            state='open'
        )
        compliance_issue = ComplianceIssue(
            scan_id=scan.id,
            nist_control='PR.AC-1',
            control_title='Access Control',
            issue_description='Test issue',
            severity='high'
        )
        
        db.session.add_all([vulnerability, port, compliance_issue])
        db.session.commit()
        
        # Delete customer (should cascade to scans and related records)
        db.session.delete(customer)
        db.session.commit()
        
        # Verify all related records are deleted
        assert Scan.query.count() == 0
        assert Vulnerability.query.count() == 0
        assert Port.query.count() == 0
        assert ComplianceIssue.query.count() == 0
