"""
Tests for API endpoints
"""

import pytest
import json
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

def test_get_customers(client):
    """Test GET /api/customers"""
    response = client.get('/api/customers')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_create_customer(client):
    """Test POST /api/customers"""
    customer_data = {
        'name': 'New Customer',
        'email': 'new@example.com',
        'organization': 'New Org'
    }
    
    response = client.post('/api/customers', 
                          data=json.dumps(customer_data),
                          content_type='application/json')
    
    assert response.status_code == 201
    
    data = json.loads(response.data)
    assert data['name'] == 'New Customer'
    assert data['email'] == 'new@example.com'
    assert data['organization'] == 'New Org'

def test_create_customer_missing_fields(client):
    """Test POST /api/customers with missing required fields"""
    customer_data = {
        'name': 'Incomplete Customer'
        # Missing email
    }
    
    response = client.post('/api/customers',
                          data=json.dumps(customer_data),
                          content_type='application/json')
    
    assert response.status_code == 400
    
    data = json.loads(response.data)
    assert 'error' in data

def test_get_customer(client, sample_customer):
    """Test GET /api/customers/<id>"""
    response = client.get(f'/api/customers/{sample_customer.id}')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['id'] == sample_customer.id
    assert data['name'] == sample_customer.name

def test_get_nonexistent_customer(client):
    """Test GET /api/customers/<id> with non-existent customer"""
    response = client.get('/api/customers/999')
    assert response.status_code == 404

def test_update_customer(client, sample_customer):
    """Test PUT /api/customers/<id>"""
    update_data = {
        'name': 'Updated Customer',
        'email': 'updated@example.com'
    }
    
    response = client.put(f'/api/customers/{sample_customer.id}',
                         data=json.dumps(update_data),
                         content_type='application/json')
    
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['name'] == 'Updated Customer'
    assert data['email'] == 'updated@example.com'

def test_delete_customer(client, sample_customer):
    """Test DELETE /api/customers/<id>"""
    response = client.delete(f'/api/customers/{sample_customer.id}')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'message' in data

def test_delete_customer_with_scans(client, sample_customer, sample_scan):
    """Test DELETE /api/customers/<id> with existing scans"""
    response = client.delete(f'/api/customers/{sample_customer.id}')
    assert response.status_code == 400
    
    data = json.loads(response.data)
    assert 'error' in data

def test_get_scans(client):
    """Test GET /api/scans"""
    response = client.get('/api/scans')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'scans' in data
    assert 'total' in data
    assert 'pages' in data

def test_get_scan(client, sample_scan):
    """Test GET /api/scans/<id>"""
    response = client.get(f'/api/scans/{sample_scan.id}')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['id'] == sample_scan.id
    assert data['name'] == sample_scan.name

def test_get_scan_vulnerabilities(client, sample_scan):
    """Test GET /api/scans/<id>/vulnerabilities"""
    # Add a vulnerability
    with client.application.app_context():
        vulnerability = Vulnerability(
            scan_id=sample_scan.id,
            title='Test Vulnerability',
            severity='high'
        )
        db.session.add(vulnerability)
        db.session.commit()
    
    response = client.get(f'/api/scans/{sample_scan.id}/vulnerabilities')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['title'] == 'Test Vulnerability'

def test_get_scan_ports(client, sample_scan):
    """Test GET /api/scans/<id>/ports"""
    # Add a port
    with client.application.app_context():
        port = Port(
            scan_id=sample_scan.id,
            port_number=80,
            protocol='tcp',
            state='open'
        )
        db.session.add(port)
        db.session.commit()
    
    response = client.get(f'/api/scans/{sample_scan.id}/ports')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['port_number'] == 80

def test_get_scan_compliance(client, sample_scan):
    """Test GET /api/scans/<id>/compliance"""
    # Add a compliance issue
    with client.application.app_context():
        compliance_issue = ComplianceIssue(
            scan_id=sample_scan.id,
            nist_control='PR.AC-1',
            control_title='Access Control',
            issue_description='Test issue',
            severity='high'
        )
        db.session.add(compliance_issue)
        db.session.commit()
    
    response = client.get(f'/api/scans/{sample_scan.id}/compliance')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['nist_control'] == 'PR.AC-1'

def test_update_vulnerability(client, sample_scan):
    """Test PUT /api/vulnerabilities/<id>"""
    # Create a vulnerability
    with client.application.app_context():
        vulnerability = Vulnerability(
            scan_id=sample_scan.id,
            title='Test Vulnerability',
            severity='high',
            status='open'
        )
        db.session.add(vulnerability)
        db.session.commit()
        vuln_id = vulnerability.id
    
    update_data = {
        'status': 'in_progress',
        'remediation': 'Apply security patch'
    }
    
    response = client.put(f'/api/vulnerabilities/{vuln_id}',
                         data=json.dumps(update_data),
                         content_type='application/json')
    
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'in_progress'
    assert data['remediation'] == 'Apply security patch'

def test_get_system_stats(client):
    """Test GET /api/system/stats"""
    response = client.get('/api/system/stats')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'cpu_percent' in data
    assert 'memory_percent' in data
    assert 'disk_percent' in data
    assert 'total_scans' in data

def test_get_logs(client):
    """Test GET /api/logs"""
    response = client.get('/api/logs')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'logs' in data
    assert 'total' in data
    assert 'pages' in data
