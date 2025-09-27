"""
NIST Framework compliance checking module
Maps vulnerabilities to NIST Cybersecurity Framework controls
"""

from typing import Dict, List, Any, Optional
from app.models import Scan, Vulnerability, ComplianceIssue, Port, db
from app.modules.logger import get_logger

logger = get_logger(__name__)

class ComplianceChecker:
    """NIST Cybersecurity Framework compliance checking"""
    
    def __init__(self):
        # NIST Framework controls mapping
        self.nist_controls = {
            'ID.AM': {
                'title': 'Asset Management',
                'controls': {
                    'ID.AM-1': 'Physical devices and systems within the organization are inventoried',
                    'ID.AM-2': 'Software platforms and applications within the organization are inventoried',
                    'ID.AM-3': 'Organizational communication and data flows are mapped',
                    'ID.AM-4': 'External information systems are catalogued',
                    'ID.AM-5': 'Resources (hardware, devices, data, and software) are prioritized based on their classification, criticality, and business value',
                    'ID.AM-6': 'Cybersecurity roles and responsibilities for the entire workforce and third-party stakeholders are established'
                }
            },
            'ID.RA': {
                'title': 'Risk Assessment',
                'controls': {
                    'ID.RA-1': 'Asset vulnerabilities are identified and documented',
                    'ID.RA-2': 'Cyber threat intelligence is received and analyzed',
                    'ID.RA-3': 'Threats, both internal and external, are identified and documented',
                    'ID.RA-4': 'Vulnerability scans are performed',
                    'ID.RA-5': 'Threats and vulnerabilities are identified and documented',
                    'ID.RA-6': 'Cybersecurity threat intelligence is received from information sharing forums and sources'
                }
            },
            'ID.GV': {
                'title': 'Governance',
                'controls': {
                    'ID.GV-1': 'Organizational cybersecurity policy is established and communicated',
                    'ID.GV-2': 'Cybersecurity roles and responsibilities are coordinated and aligned with internal roles and external partners',
                    'ID.GV-3': 'Legal and regulatory requirements regarding cybersecurity, including privacy and civil liberties obligations, are understood and managed',
                    'ID.GV-4': 'Governance and risk management processes address cybersecurity risks'
                }
            },
            'PR.AC': {
                'title': 'Access Control',
                'controls': {
                    'PR.AC-1': 'Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes',
                    'PR.AC-2': 'Physical access to assets is managed and protected',
                    'PR.AC-3': 'Remote access is managed',
                    'PR.AC-4': 'Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties',
                    'PR.AC-5': 'Network integrity is protected (e.g., network segregation, network segmentation)',
                    'PR.AC-6': 'Identities are proofed and bound to credentials and asserted in interactions',
                    'PR.AC-7': 'Users, devices, and other assets are authenticated (e.g., single-factor, multi-factor) commensurate with the risk of the transaction'
                }
            },
            'PR.AT': {
                'title': 'Awareness and Training',
                'controls': {
                    'PR.AT-1': 'All users are informed and trained',
                    'PR.AT-2': 'Privileged users understand their roles and responsibilities',
                    'PR.AT-3': 'Third-party stakeholders (e.g., suppliers, customers, partners) understand their roles and responsibilities',
                    'PR.AT-4': 'Senior executives understand their roles and responsibilities',
                    'PR.AT-5': 'Physical and cybersecurity personnel understand their roles and responsibilities'
                }
            },
            'PR.DS': {
                'title': 'Data Security',
                'controls': {
                    'PR.DS-1': 'Data-at-rest is protected',
                    'PR.DS-2': 'Data-in-transit is protected',
                    'PR.DS-3': 'Assets are formally managed throughout removal, transfers, and disposition',
                    'PR.DS-4': 'Adequate capacity to ensure availability is maintained',
                    'PR.DS-5': 'Protections against data leaks are implemented',
                    'PR.DS-6': 'Integrity checking mechanisms are used to verify software, firmware, and information integrity',
                    'PR.DS-7': 'The development and testing environment(s) are separate from the production environment',
                    'PR.DS-8': 'Integrity checking mechanisms are used to verify hardware integrity'
                }
            },
            'PR.IP': {
                'title': 'Information Protection Processes and Procedures',
                'controls': {
                    'PR.IP-1': 'A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles',
                    'PR.IP-2': 'A System Development Life Cycle to manage systems is implemented',
                    'PR.IP-3': 'Configuration change control processes are in place',
                    'PR.IP-4': 'Backup and recovery of information are conducted, tested, and maintained',
                    'PR.IP-5': 'Policy and regulations regarding the physical operating environment for organizational assets are met',
                    'PR.IP-6': 'Data is destroyed according to policy',
                    'PR.IP-7': 'Protection processes are improved',
                    'PR.IP-8': 'Effectiveness of protection technologies is shared',
                    'PR.IP-9': 'Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed',
                    'PR.IP-10': 'Response and recovery plans are tested',
                    'PR.IP-11': 'Cybersecurity is included in human resources practices',
                    'PR.IP-12': 'A vulnerability management plan is developed and implemented'
                }
            },
            'PR.MA': {
                'title': 'Maintenance',
                'controls': {
                    'PR.MA-1': 'Maintenance and repair of organizational assets are performed and logged, with approved and controlled tools',
                    'PR.MA-2': 'Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access'
                }
            },
            'PR.PT': {
                'title': 'Protective Technology',
                'controls': {
                    'PR.PT-1': 'Audit/log records are determined, documented, implemented, and reviewed in accordance with policy',
                    'PR.PT-2': 'Removable media is protected and its use restricted according to policy',
                    'PR.PT-3': 'The principle of least functionality is incorporated by configuring systems to provide only essential capabilities',
                    'PR.PT-4': 'Communications and control networks are protected',
                    'PR.PT-5': 'Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve availability requirements'
                }
            }
        }
        
        # Vulnerability to NIST control mapping
        self.vulnerability_mapping = {
            'sql_injection': ['PR.DS-1', 'PR.DS-2', 'PR.AC-4', 'PR.IP-1'],
            'xss': ['PR.DS-1', 'PR.DS-2', 'PR.AC-4', 'PR.IP-1'],
            'buffer_overflow': ['PR.IP-1', 'PR.IP-12', 'PR.PT-3'],
            'privilege_escalation': ['PR.AC-1', 'PR.AC-4', 'PR.AC-7'],
            'remote_code_execution': ['PR.AC-1', 'PR.AC-4', 'PR.IP-1', 'PR.IP-12'],
            'denial_of_service': ['PR.PT-5', 'PR.AC-5'],
            'information_disclosure': ['PR.DS-1', 'PR.DS-2', 'PR.DS-5'],
            'authentication_bypass': ['PR.AC-1', 'PR.AC-7'],
            'session_management': ['PR.AC-1', 'PR.AC-4'],
            'cryptographic_weakness': ['PR.DS-1', 'PR.DS-2', 'PR.IP-1'],
            'default_credentials': ['PR.AC-1', 'PR.AC-4', 'PR.IP-1'],
            'misconfiguration': ['PR.IP-1', 'PR.IP-3', 'PR.PT-3'],
            'outdated_software': ['PR.IP-1', 'PR.IP-12', 'PR.MA-1'],
            'unencrypted_data': ['PR.DS-1', 'PR.DS-2'],
            'weak_encryption': ['PR.DS-1', 'PR.DS-2', 'PR.IP-1']
        }
    
    def check_compliance(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Check NIST compliance for a scan
        
        Args:
            scan_id: Scan ID to check compliance for
            
        Returns:
            List of compliance issues found
        """
        try:
            logger.info(f"Starting NIST compliance check for scan {scan_id}")
            
            # Get scan and vulnerabilities
            scan = Scan.query.get(scan_id)
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
            ports = Port.query.filter_by(scan_id=scan_id).all()
            
            compliance_issues = []
            
            # Check each vulnerability against NIST controls
            for vuln in vulnerabilities:
                issues = self._check_vulnerability_compliance(vuln, scan)
                compliance_issues.extend(issues)
            
            # Check port-based compliance issues
            port_issues = self._check_port_compliance(ports, scan)
            compliance_issues.extend(port_issues)
            
            # Check general scan compliance
            general_issues = self._check_general_compliance(scan, vulnerabilities, ports)
            compliance_issues.extend(general_issues)
            
            # Save compliance issues to database
            self._save_compliance_issues(scan_id, compliance_issues)
            
            logger.info(f"NIST compliance check completed for scan {scan_id}: {len(compliance_issues)} issues found")
            return compliance_issues
            
        except Exception as e:
            logger.error(f"NIST compliance check failed for scan {scan_id}: {str(e)}")
            return []
    
    def _check_vulnerability_compliance(self, vuln: Vulnerability, scan: Scan) -> List[Dict[str, Any]]:
        """Check compliance for a specific vulnerability"""
        issues = []
        
        try:
            # Map vulnerability to NIST controls
            vuln_type = self._categorize_vulnerability(vuln)
            relevant_controls = self.vulnerability_mapping.get(vuln_type, [])
            
            for control_id in relevant_controls:
                control_info = self._get_control_info(control_id)
                if control_info:
                    issue = {
                        'nist_control': control_id,
                        'control_title': control_info['title'],
                        'issue_description': f"Vulnerability '{vuln.title}' (CVE: {vuln.cve_id or 'N/A'}) indicates non-compliance with {control_id}: {control_info['description']}",
                        'severity': self._map_vuln_severity_to_compliance(vuln.severity),
                        'recommendation': self._generate_control_recommendation(control_id, vuln),
                        'vulnerability_id': vuln.id
                    }
                    issues.append(issue)
            
            # Check for missing security controls based on vulnerability type
            missing_controls = self._identify_missing_controls(vuln_type, vuln)
            issues.extend(missing_controls)
            
        except Exception as e:
            logger.error(f"Failed to check vulnerability compliance: {str(e)}")
        
        return issues
    
    def _check_port_compliance(self, ports: List[Port], scan: Scan) -> List[Dict[str, Any]]:
        """Check compliance based on open ports"""
        issues = []
        
        try:
            # Check for unnecessary open ports
            unnecessary_ports = self._identify_unnecessary_ports(ports)
            for port_info in unnecessary_ports:
                issue = {
                    'nist_control': 'PR.AC-5',
                    'control_title': 'Network Integrity',
                    'issue_description': f"Unnecessary port {port_info['port']}/{port_info['protocol']} is open: {port_info['reason']}",
                    'severity': 'medium',
                    'recommendation': f"Close port {port_info['port']} if not required for business operations"
                }
                issues.append(issue)
            
            # Check for unencrypted services
            unencrypted_services = self._identify_unencrypted_services(ports)
            for service_info in unencrypted_services:
                issue = {
                    'nist_control': 'PR.DS-2',
                    'control_title': 'Data-in-Transit Protection',
                    'issue_description': f"Unencrypted service detected on port {service_info['port']}: {service_info['service']}",
                    'severity': 'high',
                    'recommendation': f"Implement encryption for {service_info['service']} service or use encrypted alternatives"
                }
                issues.append(issue)
            
        except Exception as e:
            logger.error(f"Failed to check port compliance: {str(e)}")
        
        return issues
    
    def _check_general_compliance(self, scan: Scan, vulnerabilities: List[Vulnerability], ports: List[Port]) -> List[Dict[str, Any]]:
        """Check general compliance issues"""
        issues = []
        
        try:
            # Check if vulnerability scanning is performed (ID.RA-4)
            if not vulnerabilities:
                issue = {
                    'nist_control': 'ID.RA-4',
                    'control_title': 'Vulnerability Scans',
                    'issue_description': 'No vulnerabilities were identified during the scan, which may indicate incomplete scanning',
                    'severity': 'medium',
                    'recommendation': 'Ensure comprehensive vulnerability scanning is performed regularly'
                }
                issues.append(issue)
            
            # Check for high-severity vulnerabilities (ID.RA-1)
            high_severity_vulns = [v for v in vulnerabilities if v.severity in ['critical', 'high']]
            if high_severity_vulns:
                issue = {
                    'nist_control': 'ID.RA-1',
                    'control_title': 'Asset Vulnerabilities',
                    'issue_description': f"{len(high_severity_vulns)} high-severity vulnerabilities identified that require immediate attention",
                    'severity': 'critical',
                    'recommendation': 'Prioritize remediation of high-severity vulnerabilities immediately'
                }
                issues.append(issue)
            
            # Check for outdated services (PR.IP-12)
            outdated_services = self._identify_outdated_services(ports)
            if outdated_services:
                issue = {
                    'nist_control': 'PR.IP-12',
                    'control_title': 'Vulnerability Management',
                    'issue_description': f"Outdated services detected: {', '.join(outdated_services)}",
                    'severity': 'medium',
                    'recommendation': 'Update all services to latest versions and implement patch management'
                }
                issues.append(issue)
            
        except Exception as e:
            logger.error(f"Failed to check general compliance: {str(e)}")
        
        return issues
    
    def _categorize_vulnerability(self, vuln: Vulnerability) -> str:
        """Categorize vulnerability type based on title and description"""
        title_lower = vuln.title.lower()
        desc_lower = (vuln.description or '').lower()
        combined_text = f"{title_lower} {desc_lower}"
        
        # Check for specific vulnerability types
        if any(keyword in combined_text for keyword in ['sql injection', 'sqli']):
            return 'sql_injection'
        elif any(keyword in combined_text for keyword in ['cross-site scripting', 'xss']):
            return 'xss'
        elif any(keyword in combined_text for keyword in ['buffer overflow', 'buffer overrun']):
            return 'buffer_overflow'
        elif any(keyword in combined_text for keyword in ['privilege escalation', 'privilege escalation']):
            return 'privilege_escalation'
        elif any(keyword in combined_text for keyword in ['remote code execution', 'rce']):
            return 'remote_code_execution'
        elif any(keyword in combined_text for keyword in ['denial of service', 'dos']):
            return 'denial_of_service'
        elif any(keyword in combined_text for keyword in ['information disclosure', 'information leak']):
            return 'information_disclosure'
        elif any(keyword in combined_text for keyword in ['authentication bypass', 'auth bypass']):
            return 'authentication_bypass'
        elif any(keyword in combined_text for keyword in ['session management', 'session hijacking']):
            return 'session_management'
        elif any(keyword in combined_text for keyword in ['cryptographic', 'encryption', 'cipher']):
            return 'cryptographic_weakness'
        elif any(keyword in combined_text for keyword in ['default credentials', 'default password']):
            return 'default_credentials'
        elif any(keyword in combined_text for keyword in ['misconfiguration', 'misconfigured']):
            return 'misconfiguration'
        elif any(keyword in combined_text for keyword in ['outdated', 'old version', 'deprecated']):
            return 'outdated_software'
        elif any(keyword in combined_text for keyword in ['unencrypted', 'plaintext']):
            return 'unencrypted_data'
        elif any(keyword in combined_text for keyword in ['weak encryption', 'weak cipher']):
            return 'weak_encryption'
        else:
            return 'general'
    
    def _get_control_info(self, control_id: str) -> Optional[Dict[str, str]]:
        """Get NIST control information"""
        for category, info in self.nist_controls.items():
            if control_id in info['controls']:
                return {
                    'title': info['title'],
                    'description': info['controls'][control_id]
                }
        return None
    
    def _map_vuln_severity_to_compliance(self, vuln_severity: str) -> str:
        """Map vulnerability severity to compliance severity"""
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'low'
        }
        return mapping.get(vuln_severity, 'medium')
    
    def _generate_control_recommendation(self, control_id: str, vuln: Vulnerability) -> str:
        """Generate specific recommendation for NIST control"""
        recommendations = {
            'PR.AC-1': 'Implement strong identity and access management controls',
            'PR.AC-4': 'Apply principle of least privilege and separation of duties',
            'PR.AC-5': 'Implement network segmentation and segregation',
            'PR.AC-7': 'Implement multi-factor authentication',
            'PR.DS-1': 'Encrypt data at rest',
            'PR.DS-2': 'Encrypt data in transit',
            'PR.DS-5': 'Implement data loss prevention controls',
            'PR.IP-1': 'Implement secure configuration management',
            'PR.IP-3': 'Implement change control processes',
            'PR.IP-12': 'Implement vulnerability management program',
            'PR.PT-3': 'Implement principle of least functionality',
            'ID.RA-1': 'Implement comprehensive asset vulnerability management',
            'ID.RA-4': 'Implement regular vulnerability scanning'
        }
        
        base_recommendation = recommendations.get(control_id, 'Implement appropriate security controls')
        return f"{base_recommendation}. Specific to this vulnerability: {vuln.remediation or 'Review and remediate the identified security issue.'}"
    
    def _identify_missing_controls(self, vuln_type: str, vuln: Vulnerability) -> List[Dict[str, Any]]:
        """Identify missing security controls based on vulnerability type"""
        issues = []
        
        # Add specific missing control recommendations based on vulnerability type
        if vuln_type in ['sql_injection', 'xss']:
            issues.append({
                'nist_control': 'PR.IP-1',
                'control_title': 'Secure Configuration',
                'issue_description': f"Web application security controls are insufficient to prevent {vuln_type}",
                'severity': 'high',
                'recommendation': 'Implement web application firewall and secure coding practices'
            })
        
        return issues
    
    def _identify_unnecessary_ports(self, ports: List[Port]) -> List[Dict[str, Any]]:
        """Identify potentially unnecessary open ports"""
        unnecessary = []
        
        # Common unnecessary ports
        unnecessary_port_ranges = {
            (135, 139): 'NetBIOS ports - often unnecessary',
            (445, 445): 'SMB port - ensure it\'s properly secured',
            (23, 23): 'Telnet - use SSH instead',
            (21, 21): 'FTP - use SFTP instead',
            (80, 80): 'HTTP - ensure it redirects to HTTPS',
            (1433, 1433): 'SQL Server - ensure it\'s properly secured',
            (3389, 3389): 'RDP - ensure it\'s properly secured'
        }
        
        for port in ports:
            if port.state == 'open':
                port_num = port.port_number
                for (start, end), reason in unnecessary_port_ranges.items():
                    if start <= port_num <= end:
                        unnecessary.append({
                            'port': port_num,
                            'protocol': port.protocol,
                            'reason': reason
                        })
                        break
        
        return unnecessary
    
    def _identify_unencrypted_services(self, ports: List[Port]) -> List[Dict[str, Any]]:
        """Identify services that should be encrypted"""
        unencrypted = []
        
        unencrypted_services = {
            'http': 'Use HTTPS instead',
            'ftp': 'Use SFTP instead',
            'telnet': 'Use SSH instead',
            'pop3': 'Use POP3S instead',
            'imap': 'Use IMAPS instead',
            'smtp': 'Use SMTPS instead'
        }
        
        for port in ports:
            if port.state == 'open' and port.service:
                service_lower = port.service.lower()
                for unencrypted_service, recommendation in unencrypted_services.items():
                    if unencrypted_service in service_lower:
                        unencrypted.append({
                            'port': port.port_number,
                            'service': port.service,
                            'recommendation': recommendation
                        })
                        break
        
        return unencrypted
    
    def _identify_outdated_services(self, ports: List[Port]) -> List[str]:
        """Identify potentially outdated services"""
        outdated = []
        
        for port in ports:
            if port.state == 'open' and port.version:
                version_lower = port.version.lower()
                if any(keyword in version_lower for keyword in ['old', 'deprecated', 'legacy', 'v1.0', 'v2.0']):
                    outdated.append(f"{port.service} {port.version} on port {port.port_number}")
        
        return outdated
    
    def _save_compliance_issues(self, scan_id: int, issues: List[Dict[str, Any]]) -> None:
        """Save compliance issues to database"""
        try:
            for issue in issues:
                compliance_issue = ComplianceIssue(
                    scan_id=scan_id,
                    nist_control=issue['nist_control'],
                    control_title=issue['control_title'],
                    issue_description=issue['issue_description'],
                    severity=issue['severity'],
                    recommendation=issue['recommendation']
                )
                db.session.add(compliance_issue)
            
            db.session.commit()
            logger.info(f"Saved {len(issues)} compliance issues for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save compliance issues: {str(e)}")
            raise
