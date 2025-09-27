"""
Report generation routes
Handles PDF report generation and export
"""

from flask import Blueprint, request, jsonify, send_file, current_app
from app import db
from app.models import Scan, Customer, Vulnerability, Port, ComplianceIssue
from app.modules.pdf_generator import PDFGenerator
from app.modules.logger import get_logger
import json
import os
from io import BytesIO

report_bp = Blueprint('report', __name__)
logger = get_logger(__name__)

@report_bp.route('/<int:scan_id>/generate', methods=['POST'])
def generate_report(scan_id):
    """Generate PDF report for a scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan must be completed to generate report'}), 400
        
        # Get report options
        data = request.get_json() or {}
        engine = data.get('engine', 'weasyprint')  # Default to weasyprint
        include_vulnerabilities = data.get('include_vulnerabilities', True)
        include_ports = data.get('include_ports', True)
        include_compliance = data.get('include_compliance', True)
        include_osint = data.get('include_osint', True)
        
        # Generate PDF
        pdf_generator = PDFGenerator()
        pdf_content = pdf_generator.generate_scan_report(scan_id, engine=engine)
        
        # Save to temporary file
        temp_filename = f"scan_report_{scan_id}_{scan.created_at.strftime('%Y%m%d_%H%M%S')}.pdf"
        temp_path = os.path.join(current_app.config.get('TEMP_DIR', '/tmp'), temp_filename)
        
        with open(temp_path, 'wb') as f:
            f.write(pdf_content)
        
        logger.info(f"Generated PDF report for scan {scan_id}")
        
        return jsonify({
            'message': 'Report generated successfully',
            'filename': temp_filename,
            'download_url': f'/report/{scan_id}/download/{temp_filename}'
        })
    
    except Exception as e:
        logger.error(f"Error generating report for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@report_bp.route('/<int:scan_id>/download/<filename>', methods=['GET'])
def download_report(scan_id, filename):
    """Download a generated report"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # Validate filename
        if not filename.startswith(f"scan_report_{scan_id}_"):
            return jsonify({'error': 'Invalid filename'}), 400
        
        temp_path = os.path.join(current_app.config.get('TEMP_DIR', '/tmp'), filename)
        
        if not os.path.exists(temp_path):
            return jsonify({'error': 'Report file not found'}), 404
        
        logger.info(f"Downloaded report for scan {scan_id}")
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
    
    except Exception as e:
        logger.error(f"Error downloading report for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to download report'}), 500

@report_bp.route('/<int:scan_id>/preview', methods=['GET'])
def preview_report(scan_id):
    """Get report preview data"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        customer = Customer.query.get(scan.customer_id)
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        ports = Port.query.filter_by(scan_id=scan_id).all()
        compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
        
        # Generate summary statistics
        vuln_by_severity = {
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low']),
            'info': len([v for v in vulnerabilities if v.severity == 'info'])
        }
        
        compliance_by_severity = {
            'critical': len([c for c in compliance_issues if c.severity == 'critical']),
            'high': len([c for c in compliance_issues if c.severity == 'high']),
            'medium': len([c for c in compliance_issues if c.severity == 'medium']),
            'low': len([c for c in compliance_issues if c.severity == 'low'])
        }
        
        # Calculate risk score
        risk_score = 0
        risk_score += vuln_by_severity['critical'] * 25
        risk_score += vuln_by_severity['high'] * 15
        risk_score += vuln_by_severity['medium'] * 8
        risk_score += vuln_by_severity['low'] * 3
        risk_score += vuln_by_severity['info'] * 1
        
        risk_score += compliance_by_severity['critical'] * 20
        risk_score += compliance_by_severity['high'] * 10
        risk_score += compliance_by_severity['medium'] * 5
        risk_score += compliance_by_severity['low'] * 2
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 80:
            risk_level = 'Critical'
        elif risk_score >= 60:
            risk_level = 'High'
        elif risk_score >= 40:
            risk_level = 'Medium'
        elif risk_score >= 20:
            risk_level = 'Low'
        else:
            risk_level = 'Very Low'
        
        preview_data = {
            'scan': scan.to_dict(),
            'customer': customer.to_dict() if customer else None,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'total_ports': len([p for p in ports if p.state == 'open']),
                'total_compliance_issues': len(compliance_issues),
                'vulnerability_counts': vuln_by_severity,
                'compliance_counts': compliance_by_severity,
                'risk_score': risk_score,
                'risk_level': risk_level
            },
            'vulnerabilities': [v.to_dict() for v in vulnerabilities[:10]],  # First 10
            'ports': [p.to_dict() for p in ports[:20]],  # First 20
            'compliance_issues': [c.to_dict() for c in compliance_issues[:10]]  # First 10
        }
        
        return jsonify(preview_data)
    
    except Exception as e:
        logger.error(f"Error getting report preview for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get report preview'}), 500

@report_bp.route('/<int:scan_id>/edit', methods=['GET'])
def edit_report(scan_id):
    """Get editable report data"""
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
        
        # Group compliance issues by severity
        compliance_by_severity = {
            'critical': [c for c in compliance_issues if c.severity == 'critical'],
            'high': [c for c in compliance_issues if c.severity == 'high'],
            'medium': [c for c in compliance_issues if c.severity == 'medium'],
            'low': [c for c in compliance_issues if c.severity == 'low']
        }
        
        edit_data = {
            'scan': scan.to_dict(),
            'customer': customer.to_dict() if customer else None,
            'vulnerabilities': [v.to_dict() for v in vulnerabilities],
            'ports': [p.to_dict() for p in ports],
            'compliance_issues': [c.to_dict() for c in compliance_issues],
            'vuln_by_severity': {k: [v.to_dict() for v in v_list] for k, v_list in vuln_by_severity.items()},
            'compliance_by_severity': {k: [c.to_dict() for c in c_list] for k, c_list in compliance_by_severity.items()}
        }
        
        return jsonify(edit_data)
    
    except Exception as e:
        logger.error(f"Error getting editable report data for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get editable report data'}), 500

@report_bp.route('/<int:scan_id>/save', methods=['POST'])
def save_report_edits(scan_id):
    """Save report edits"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update scan information
        if 'scan' in data:
            scan_data = data['scan']
            if 'name' in scan_data:
                scan.name = scan_data['name']
        
        # Update vulnerabilities
        if 'vulnerabilities' in data:
            for vuln_data in data['vulnerabilities']:
                vuln = Vulnerability.query.get(vuln_data['id'])
                if vuln:
                    if 'status' in vuln_data:
                        vuln.status = vuln_data['status']
                    if 'remediation' in vuln_data:
                        vuln.remediation = vuln_data['remediation']
                    if 'title' in vuln_data:
                        vuln.title = vuln_data['title']
                    if 'description' in vuln_data:
                        vuln.description = vuln_data['description']
        
        # Update compliance issues
        if 'compliance_issues' in data:
            for compliance_data in data['compliance_issues']:
                compliance = ComplianceIssue.query.get(compliance_data['id'])
                if compliance:
                    if 'status' in compliance_data:
                        compliance.status = compliance_data['status']
                    if 'recommendation' in compliance_data:
                        compliance.recommendation = compliance_data['recommendation']
                    if 'issue_description' in compliance_data:
                        compliance.issue_description = compliance_data['issue_description']
        
        db.session.commit()
        
        logger.info(f"Saved report edits for scan {scan_id}")
        
        return jsonify({'message': 'Report edits saved successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving report edits for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to save report edits'}), 500

@report_bp.route('/<int:scan_id>/export', methods=['POST'])
def export_report(scan_id):
    """Export report in various formats"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        data = request.get_json() or {}
        format_type = data.get('format', 'pdf')
        
        if format_type == 'pdf':
            # Generate PDF
            pdf_generator = PDFGenerator()
            pdf_content = pdf_generator.generate_scan_report(scan_id)
            
            return send_file(
                BytesIO(pdf_content),
                as_attachment=True,
                download_name=f"scan_report_{scan_id}.pdf",
                mimetype='application/pdf'
            )
        
        elif format_type == 'json':
            # Export as JSON
            scan_data = scan.to_dict()
            customer = Customer.query.get(scan.customer_id)
            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
            ports = Port.query.filter_by(scan_id=scan_id).all()
            compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
            
            export_data = {
                'scan': scan_data,
                'customer': customer.to_dict() if customer else None,
                'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                'ports': [p.to_dict() for p in ports],
                'compliance_issues': [c.to_dict() for c in compliance_issues],
                'exported_at': db.func.now().isoformat()
            }
            
            return send_file(
                BytesIO(json.dumps(export_data, indent=2).encode()),
                as_attachment=True,
                download_name=f"scan_report_{scan_id}.json",
                mimetype='application/json'
            )
        
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
    
    except Exception as e:
        logger.error(f"Error exporting report for scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to export report'}), 500
