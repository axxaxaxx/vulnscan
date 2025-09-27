"""
PDF Report Generator
Handles generation of PDF reports for scans and other data
"""

import os
import json
from datetime import datetime
from app.modules.logger import get_logger

logger = get_logger(__name__)

class PDFGenerator:
    def __init__(self):
        """Initialize PDF generator with available engines"""
        self.engine = None
        self.available_engines = []
        
        # Try WeasyPrint first (preferred)
        try:
            from weasyprint import HTML, CSS
            self.weasyprint_available = True
            self.available_engines.append('weasyprint')
            logger.info("WeasyPrint PDF engine available")
        except ImportError as e:
            self.weasyprint_available = False
            logger.warning(f"WeasyPrint not available: {e}")
        
        # Try ReportLab as fallback
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            self.reportlab_available = True
            self.available_engines.append('reportlab')
            logger.info("ReportLab PDF engine available")
        except ImportError as e:
            self.reportlab_available = False
            logger.warning(f"ReportLab not available: {e}")
        
        if not self.available_engines:
            raise ImportError("No PDF generation engines available. Please install WeasyPrint or ReportLab.")
        
        # Use WeasyPrint if available, otherwise ReportLab
        self.engine = 'weasyprint' if self.weasyprint_available else 'reportlab'
        logger.info(f"Using PDF engine: {self.engine}")

    def generate_scan_report(self, scan_data):
        """Generate a comprehensive scan report PDF"""
        try:
            if self.engine == 'weasyprint':
                return self._generate_with_weasyprint(scan_data)
            elif self.engine == 'reportlab':
                return self._generate_with_reportlab(scan_data)
            else:
                raise ValueError(f"Unknown PDF engine: {self.engine}")
        except Exception as e:
            logger.error(f"Error generating scan report: {str(e)}")
            # Fallback to ReportLab if WeasyPrint fails
            if self.engine == 'weasyprint' and self.reportlab_available:
                logger.info("WeasyPrint failed, falling back to ReportLab")
                self.engine = 'reportlab'
                return self._generate_with_reportlab(scan_data)
            else:
                raise

    def _generate_with_weasyprint(self, scan_data):
        """Generate PDF using WeasyPrint"""
        try:
            from weasyprint import HTML, CSS
            
            html_content = self._generate_html_report(scan_data)
            css_content = self._get_css_styles()
            
            # Create HTML document
            html_doc = HTML(string=html_content)
            
            # Create CSS document
            css_doc = CSS(string=css_content)
            
            # Generate PDF
            pdf_bytes = html_doc.write_pdf(stylesheets=[css_doc])
            
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"WeasyPrint error: {str(e)}")
            raise

    def _generate_with_reportlab(self, scan_data):
        """Generate PDF using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from io import BytesIO
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            # Get styles
            styles = getSampleStyleSheet()
            
            # Create custom styles
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
                textColor=colors.darkblue
            )
            
            # Build content
            story = []
            
            # Title
            story.append(Paragraph("Vulnerability Scan Report", title_style))
            story.append(Spacer(1, 12))
            
            # Scan information
            scan = scan_data['scan']
            customer = scan_data['customer']
            
            scan_info = [
                ['Scan Name:', scan.get('name', 'N/A')],
                ['Target:', scan.get('target', 'N/A')],
                ['Scan Type:', scan.get('scan_type', 'N/A')],
                ['Status:', scan.get('status', 'N/A')],
                ['Created:', scan.get('created_at', 'N/A')],
                ['Completed:', scan.get('completed_at', 'N/A')],
            ]
            
            if customer:
                scan_info.extend([
                    ['Customer:', customer.get('name', 'N/A')],
                    ['Organization:', customer.get('organization', 'N/A')],
                    ['Email:', customer.get('email', 'N/A')]
                ])
            
            scan_info.append(['Report Generated:', scan_data.get('generated_at', 'N/A')])
            
            scan_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(scan_table)
            story.append(Spacer(1, 20))
            
            # Ports section
            ports = scan_data.get('ports', [])
            if ports:
                story.append(Paragraph("Open Ports", heading_style))
                
                port_data = [['Port', 'Protocol', 'State', 'Service', 'Version']]
                for port in ports:
                    port_data.append([
                        str(port.get('port_number', '')),
                        port.get('protocol', ''),
                        port.get('state', ''),
                        port.get('service', ''),
                        port.get('version', '')
                    ])
                
                port_table = Table(port_data, colWidths=[0.8*inch, 0.8*inch, 0.8*inch, 1.5*inch, 2*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(port_table)
                story.append(Spacer(1, 20))
            
            # Vulnerabilities section
            vulnerabilities = scan_data.get('vulnerabilities', [])
            if vulnerabilities:
                story.append(Paragraph("Vulnerabilities", heading_style))
                
                vuln_data = [['CVE ID', 'Severity', 'Title', 'CVSS Score']]
                for vuln in vulnerabilities:
                    vuln_data.append([
                        vuln.get('cve_id', 'N/A'),
                        vuln.get('severity', 'N/A'),
                        vuln.get('title', 'N/A')[:50] + '...' if len(vuln.get('title', '')) > 50 else vuln.get('title', 'N/A'),
                        str(vuln.get('cvss_score', 'N/A'))
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[1.2*inch, 0.8*inch, 3*inch, 0.8*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 20))
            
            # Searchsploit results section
            searchsploit_results = scan_data.get('searchsploit_results', [])
            if searchsploit_results:
                story.append(Paragraph("Searchsploit Results", heading_style))
                
                sploit_data = [['Exploit ID', 'Title', 'Platform', 'Port']]
                for result in searchsploit_results:
                    sploit_data.append([
                        result.get('exploit_id', 'N/A'),
                        result.get('title', 'N/A')[:40] + '...' if len(result.get('title', '')) > 40 else result.get('title', 'N/A'),
                        result.get('platform', 'N/A'),
                        str(result.get('port', 'N/A'))
                    ])
                
                sploit_table = Table(sploit_data, colWidths=[1.2*inch, 2.5*inch, 1*inch, 0.8*inch])
                sploit_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(sploit_table)
                story.append(Spacer(1, 20))
            
            # OSINT results section
            osint_results = scan_data.get('osint_results', {})
            if osint_results:
                story.append(Paragraph("OSINT Results", heading_style))
                
                for category, results in osint_results.items():
                    if results:
                        story.append(Paragraph(f"{category.title()} ({len(results)})", heading_style))
                        
                        osint_data = [['Source', 'Title', 'Confidence', 'URL']]
                        for result in results:
                            url = result.get('url', '')
                            if len(url) > 30:
                                url = url[:30] + '...'
                            osint_data.append([
                                result.get('source', 'N/A'),
                                result.get('title', 'N/A')[:30] + '...' if len(result.get('title', '')) > 30 else result.get('title', 'N/A'),
                                str(result.get('confidence', 'N/A')) + '%' if result.get('confidence') else 'N/A',
                                url
                            ])
                        
                        osint_table = Table(osint_data, colWidths=[1*inch, 1.5*inch, 0.8*inch, 2*inch])
                        osint_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        
                        story.append(osint_table)
                        story.append(Spacer(1, 15))
            
            # Compliance issues section
            compliance_issues = scan_data.get('compliance_issues', [])
            if compliance_issues:
                story.append(Paragraph("Compliance Issues", heading_style))
                
                comp_data = [['Category', 'Severity', 'Description']]
                for issue in compliance_issues:
                    comp_data.append([
                        issue.get('category', 'N/A'),
                        issue.get('severity', 'N/A'),
                        issue.get('description', 'N/A')[:60] + '...' if len(issue.get('description', '')) > 60 else issue.get('description', 'N/A')
                    ])
                
                comp_table = Table(comp_data, colWidths=[1.5*inch, 0.8*inch, 3.5*inch])
                comp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(comp_table)
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            return buffer.getvalue()
            
        except Exception as e:
            logger.error(f"ReportLab error: {str(e)}")
            raise

    def _generate_html_report(self, scan_data):
        """Generate HTML content for WeasyPrint"""
        scan = scan_data['scan']
        customer = scan_data['customer']
        vulnerabilities = scan_data.get('vulnerabilities', [])
        ports = scan_data.get('ports', [])
        compliance_issues = scan_data.get('compliance_issues', [])
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Vulnerability Scan Report</title>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Scan Report</h1>
                <p>Generated on: {scan_data.get('generated_at', 'N/A')}</p>
            </div>
            
            <div class="section">
                <h2>Scan Information</h2>
                <table class="info-table">
                    <tr><td><strong>Scan Name:</strong></td><td>{scan.get('name', 'N/A')}</td></tr>
                    <tr><td><strong>Target:</strong></td><td>{scan.get('target', 'N/A')}</td></tr>
                    <tr><td><strong>Scan Type:</strong></td><td>{scan.get('scan_type', 'N/A')}</td></tr>
                    <tr><td><strong>Status:</strong></td><td>{scan.get('status', 'N/A')}</td></tr>
                    <tr><td><strong>Created:</strong></td><td>{scan.get('created_at', 'N/A')}</td></tr>
                    <tr><td><strong>Completed:</strong></td><td>{scan.get('completed_at', 'N/A')}</td></tr>
        """
        
        if customer:
            html += f"""
                    <tr><td><strong>Customer:</strong></td><td>{customer.get('name', 'N/A')}</td></tr>
                    <tr><td><strong>Organization:</strong></td><td>{customer.get('organization', 'N/A')}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{customer.get('email', 'N/A')}</td></tr>
            """
        
        html += """
                </table>
            </div>
        """
        
        # Ports section
        if ports:
            html += """
            <div class="section">
                <h2>Open Ports</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for port in ports:
                html += f"""
                        <tr>
                            <td>{port.get('port_number', '')}</td>
                            <td>{port.get('protocol', '')}</td>
                            <td>{port.get('state', '')}</td>
                            <td>{port.get('service', '')}</td>
                            <td>{port.get('version', '')}</td>
                        </tr>
                """
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        # Vulnerabilities section
        if vulnerabilities:
            html += """
            <div class="section">
                <h2>Vulnerabilities</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>CVSS Score</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for vuln in vulnerabilities:
                html += f"""
                        <tr>
                            <td>{vuln.get('cve_id', 'N/A')}</td>
                            <td>{vuln.get('severity', 'N/A')}</td>
                            <td>{vuln.get('title', 'N/A')}</td>
                            <td>{vuln.get('cvss_score', 'N/A')}</td>
                        </tr>
                """
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        # Searchsploit results section
        searchsploit_results = scan_data.get('searchsploit_results', [])
        if searchsploit_results:
            html += """
            <div class="section">
                <h2>Searchsploit Results</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Exploit ID</th>
                            <th>Title</th>
                            <th>Platform</th>
                            <th>Port</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for result in searchsploit_results:
                html += f"""
                        <tr>
                            <td>{result.get('exploit_id', 'N/A')}</td>
                            <td>{result.get('title', 'N/A')}</td>
                            <td>{result.get('platform', 'N/A')}</td>
                            <td>{result.get('port', 'N/A')}</td>
                        </tr>
                """
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        # OSINT results section
        osint_results = scan_data.get('osint_results', {})
        if osint_results:
            html += """
            <div class="section">
                <h2>OSINT Results</h2>
            """
            for category, results in osint_results.items():
                if results:
                    html += f"""
                    <h3>{category.title()} ({len(results)})</h3>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Title</th>
                                <th>Confidence</th>
                                <th>URL</th>
                            </tr>
                        </thead>
                        <tbody>
                    """
                    for result in results:
                        html += f"""
                            <tr>
                                <td>{result.get('source', 'N/A')}</td>
                                <td>{result.get('title', 'N/A')}</td>
                                <td>{result.get('confidence', 'N/A')}%</td>
                                <td>{result.get('url', 'N/A')}</td>
                            </tr>
                        """
                    html += """
                        </tbody>
                    </table>
                    """
            html += """
            </div>
            """
        
        # Compliance issues section
        if compliance_issues:
            html += """
            <div class="section">
                <h2>Compliance Issues</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for issue in compliance_issues:
                html += f"""
                        <tr>
                            <td>{issue.get('category', 'N/A')}</td>
                            <td>{issue.get('severity', 'N/A')}</td>
                            <td>{issue.get('description', 'N/A')}</td>
                        </tr>
                """
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html

    def _get_css_styles(self):
        """Get CSS styles for WeasyPrint"""
        return """
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            color: #333;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
        }
        
        .header h1 {
            color: #007bff;
            margin: 0;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #007bff;
            border-bottom: 1px solid #ccc;
            padding-bottom: 5px;
        }
        
        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        .info-table td {
            padding: 8px;
            border: 1px solid #ddd;
        }
        
        .info-table td:first-child {
            background-color: #f8f9fa;
            font-weight: bold;
            width: 30%;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        .data-table th,
        .data-table td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }
        
        .data-table th {
            background-color: #007bff;
            color: white;
            font-weight: bold;
        }
        
        .data-table tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        .data-table tr:hover {
            background-color: #e9ecef;
        }
        """