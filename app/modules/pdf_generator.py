"""
PDF report generation module
Handles generation of vulnerability scan reports in PDF format
"""

from io import BytesIO
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    WEASYPRINT_AVAILABLE = False
    WEASYPRINT_ERROR = str(e)

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from app.models import Scan, Customer, Vulnerability, Port, ComplianceIssue
from app.modules.logger import get_logger

logger = get_logger(__name__)

class PDFGenerator:
    """PDF report generation functionality"""
    
    def __init__(self):
        self.available_engines = []
        
        if WEASYPRINT_AVAILABLE:
            self.available_engines.append('weasyprint')
        else:
            logger.warning(f"WeasyPrint not available: {WEASYPRINT_ERROR if 'WEASYPRINT_ERROR' in globals() else 'Import failed'}")
        
        if REPORTLAB_AVAILABLE:
            self.available_engines.append('reportlab')
        
        if not self.available_engines:
            error_msg = "No PDF generation engines available. "
            if not WEASYPRINT_AVAILABLE and not REPORTLAB_AVAILABLE:
                error_msg += "Install weasyprint (with system dependencies) or reportlab."
            elif not WEASYPRINT_AVAILABLE:
                error_msg += f"WeasyPrint failed: {WEASYPRINT_ERROR if 'WEASYPRINT_ERROR' in globals() else 'Import failed'}. Install system dependencies or use reportlab."
            else:
                error_msg += "Install reportlab."
            raise Exception(error_msg)
        
        logger.info(f"PDF generation engines available: {', '.join(self.available_engines)}")
    
    def generate_scan_report(self, scan_id: int, engine: str = None) -> bytes:
        """
        Generate PDF report for a scan
        
        Args:
            scan_id: Scan ID to generate report for
            engine: PDF engine to use (weasyprint or reportlab)
            
        Returns:
            PDF content as bytes
        """
        try:
            # Get scan data
            scan_data = self._get_scan_data(scan_id)
            if not scan_data:
                raise Exception(f"Scan {scan_id} not found")
            
            # Choose engine
            if not engine:
                engine = self.available_engines[0]
            
            if engine not in self.available_engines:
                raise Exception(f"PDF engine {engine} not available")
            
            logger.info(f"Generating PDF report for scan {scan_id} using {engine}")
            
            if engine == 'weasyprint':
                return self._generate_with_weasyprint(scan_data)
            elif engine == 'reportlab':
                return self._generate_with_reportlab(scan_data)
            else:
                raise Exception(f"Unknown PDF engine: {engine}")
                
        except Exception as e:
            logger.error(f"PDF generation failed for scan {scan_id}: {str(e)}")
            raise
    
    def _get_scan_data(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get comprehensive scan data for report generation"""
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return None
            
            customer = Customer.query.get(scan.customer_id)
            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
            ports = Port.query.filter_by(scan_id=scan_id).all()
            compliance_issues = ComplianceIssue.query.filter_by(scan_id=scan_id).all()
            
            # Categorize vulnerabilities by severity
            vuln_by_severity = {
                'critical': [v for v in vulnerabilities if v.severity == 'critical'],
                'high': [v for v in vulnerabilities if v.severity == 'high'],
                'medium': [v for v in vulnerabilities if v.severity == 'medium'],
                'low': [v for v in vulnerabilities if v.severity == 'low'],
                'info': [v for v in vulnerabilities if v.severity == 'info']
            }
            
            # Categorize compliance issues by severity
            compliance_by_severity = {
                'critical': [c for c in compliance_issues if c.severity == 'critical'],
                'high': [c for c in compliance_issues if c.severity == 'high'],
                'medium': [c for c in compliance_issues if c.severity == 'medium'],
                'low': [c for c in compliance_issues if c.severity == 'low']
            }
            
            return {
                'scan': scan.to_dict(),
                'customer': customer.to_dict() if customer else None,
                'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                'ports': [p.to_dict() for p in ports],
                'compliance_issues': [c.to_dict() for c in compliance_issues],
                'vuln_by_severity': {k: [v.to_dict() for v in v_list] for k, v_list in vuln_by_severity.items()},
                'compliance_by_severity': {k: [c.to_dict() for c in c_list] for k, c_list in compliance_by_severity.items()},
                'summary': self._generate_summary(scan, vulnerabilities, ports, compliance_issues)
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan data: {str(e)}")
            return None
    
    def _generate_summary(self, scan: Scan, vulnerabilities: List[Vulnerability], 
                         ports: List[Port], compliance_issues: List[ComplianceIssue]) -> Dict[str, Any]:
        """Generate executive summary"""
        total_vulns = len(vulnerabilities)
        total_ports = len([p for p in ports if p.state == 'open'])
        total_compliance_issues = len(compliance_issues)
        
        vuln_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low']),
            'info': len([v for v in vulnerabilities if v.severity == 'info'])
        }
        
        compliance_counts = {
            'critical': len([c for c in compliance_issues if c.severity == 'critical']),
            'high': len([c for c in compliance_issues if c.severity == 'high']),
            'medium': len([c for c in compliance_issues if c.severity == 'medium']),
            'low': len([c for c in compliance_issues if c.severity == 'low'])
        }
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(vuln_counts, compliance_counts)
        
        return {
            'total_vulnerabilities': total_vulns,
            'total_ports': total_ports,
            'total_compliance_issues': total_compliance_issues,
            'vulnerability_counts': vuln_counts,
            'compliance_counts': compliance_counts,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'scan_duration': self._calculate_scan_duration(scan),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _calculate_risk_score(self, vuln_counts: Dict[str, int], compliance_counts: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Vulnerability scoring
        score += vuln_counts['critical'] * 25
        score += vuln_counts['high'] * 15
        score += vuln_counts['medium'] * 8
        score += vuln_counts['low'] * 3
        score += vuln_counts['info'] * 1
        
        # Compliance scoring
        score += compliance_counts['critical'] * 20
        score += compliance_counts['high'] * 10
        score += compliance_counts['medium'] * 5
        score += compliance_counts['low'] * 2
        
        return min(score, 100)
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on score"""
        if risk_score >= 80:
            return 'Critical'
        elif risk_score >= 60:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        elif risk_score >= 20:
            return 'Low'
        else:
            return 'Very Low'
    
    def _calculate_scan_duration(self, scan: Scan) -> str:
        """Calculate scan duration"""
        if scan.started_at and scan.completed_at:
            duration = scan.completed_at - scan.started_at
            return str(duration)
        elif scan.started_at:
            duration = datetime.utcnow() - scan.started_at
            return f"{str(duration)} (ongoing)"
        else:
            return "Not started"
    
    def _generate_with_weasyprint(self, scan_data: Dict[str, Any]) -> bytes:
        """Generate PDF using WeasyPrint"""
        try:
            html_content = self._generate_html_content(scan_data)
            css_content = self._generate_css_content()
            
            # Generate PDF
            font_config = FontConfiguration()
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)
            
            pdf_bytes = html_doc.write_pdf(stylesheets=[css_doc], font_config=font_config)
            
            logger.info("PDF generated successfully with WeasyPrint")
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"WeasyPrint PDF generation failed: {str(e)}")
            raise
    
    def _generate_with_reportlab(self, scan_data: Dict[str, Any]) -> bytes:
        """Generate PDF using ReportLab"""
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, 
                                  topMargin=72, bottomMargin=18)
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.darkblue
            )
            
            # Build content
            story = []
            
            # Title
            story.append(Paragraph("Vulnerability Scan Report", title_style))
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            summary = scan_data['summary']
            summary_text = f"""
            <b>Target:</b> {scan_data['scan']['target']}<br/>
            <b>Scan Date:</b> {scan_data['scan']['created_at']}<br/>
            <b>Risk Level:</b> {summary['risk_level']} ({summary['risk_score']}/100)<br/>
            <b>Total Vulnerabilities:</b> {summary['total_vulnerabilities']}<br/>
            <b>Open Ports:</b> {summary['total_ports']}<br/>
            <b>Compliance Issues:</b> {summary['total_compliance_issues']}<br/>
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Vulnerability Summary Table
            story.append(Paragraph("Vulnerability Summary", heading_style))
            vuln_data = [
                ['Severity', 'Count'],
                ['Critical', str(summary['vulnerability_counts']['critical'])],
                ['High', str(summary['vulnerability_counts']['high'])],
                ['Medium', str(summary['vulnerability_counts']['medium'])],
                ['Low', str(summary['vulnerability_counts']['low'])],
                ['Info', str(summary['vulnerability_counts']['info'])]
            ]
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
            
            # Detailed Vulnerabilities
            if scan_data['vulnerabilities']:
                story.append(Paragraph("Detailed Vulnerabilities", heading_style))
                
                for vuln in scan_data['vulnerabilities'][:10]:  # Limit to first 10
                    vuln_text = f"""
                    <b>{vuln['title']}</b><br/>
                    <b>CVE:</b> {vuln['cve_id'] or 'N/A'}<br/>
                    <b>Severity:</b> {vuln['severity'].upper()}<br/>
                    <b>CVSS Score:</b> {vuln['cvss_score'] or 'N/A'}<br/>
                    <b>Description:</b> {vuln['description'] or 'No description available'}<br/>
                    <b>Remediation:</b> {vuln['remediation'] or 'No remediation available'}<br/>
                    """
                    story.append(Paragraph(vuln_text, styles['Normal']))
                    story.append(Spacer(1, 10))
            
            # Compliance Issues
            if scan_data['compliance_issues']:
                story.append(PageBreak())
                story.append(Paragraph("NIST Compliance Issues", heading_style))
                
                for issue in scan_data['compliance_issues'][:10]:  # Limit to first 10
                    issue_text = f"""
                    <b>{issue['nist_control']}: {issue['control_title']}</b><br/>
                    <b>Severity:</b> {issue['severity'].upper()}<br/>
                    <b>Issue:</b> {issue['issue_description']}<br/>
                    <b>Recommendation:</b> {issue['recommendation']}<br/>
                    """
                    story.append(Paragraph(issue_text, styles['Normal']))
                    story.append(Spacer(1, 10))
            
            # Build PDF
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info("PDF generated successfully with ReportLab")
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"ReportLab PDF generation failed: {str(e)}")
            raise
    
    def _generate_html_content(self, scan_data: Dict[str, Any]) -> str:
        """Generate HTML content for WeasyPrint"""
        # This is a simplified HTML template
        # In production, you would use a proper templating engine like Jinja2
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Vulnerability Scan Report</title>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> {scan_data['scan']['target']}</p>
            <p><strong>Scan Date:</strong> {scan_data['scan']['created_at']}</p>
            <p><strong>Risk Level:</strong> {scan_data['summary']['risk_level']} ({scan_data['summary']['risk_score']}/100)</p>
            <p><strong>Total Vulnerabilities:</strong> {scan_data['summary']['total_vulnerabilities']}</p>
            <p><strong>Open Ports:</strong> {scan_data['summary']['total_ports']}</p>
            <p><strong>Compliance Issues:</strong> {scan_data['summary']['total_compliance_issues']}</p>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Title</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>CVSS Score</th>
                </tr>
        """
        
        for vuln in scan_data['vulnerabilities'][:20]:  # Limit to first 20
            html_template += f"""
                <tr>
                    <td>{vuln['title']}</td>
                    <td>{vuln['cve_id'] or 'N/A'}</td>
                    <td>{vuln['severity'].upper()}</td>
                    <td>{vuln['cvss_score'] or 'N/A'}</td>
                </tr>
            """
        
        html_template += """
            </table>
        </body>
        </html>
        """
        
        return html_template
    
    def _generate_css_content(self) -> str:
        """Generate CSS content for WeasyPrint"""
        return """
        @page {
            size: A4;
            margin: 2cm;
        }
        
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #f39c12; font-weight: bold; }
        .medium { color: #f1c40f; font-weight: bold; }
        .low { color: #27ae60; }
        .info { color: #3498db; }
        """
