"""
Nmap scanning module
Handles port scanning and service detection using python-nmap
"""

import nmap
import json
from typing import Dict, List, Any
from app.models import Scan, Port, db
from app.modules.logger import get_logger

logger = get_logger(__name__)

class NmapScanner:
    """Nmap scanning functionality"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_target(self, target: str, scan_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform nmap scan on target
        
        Args:
            target: IP address or hostname to scan
            scan_options: Dictionary of nmap options
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Default scan options
            default_options = {
                'ports': '1-1000',
                'arguments': '-sS -sV -O --script vuln'
            }
            
            if scan_options:
                default_options.update(scan_options)
            
            # Build nmap command
            ports = default_options.get('ports', '1-1000')
            arguments = default_options.get('arguments', '-sS -sV -O --script vuln')
            
            logger.info(f"Starting nmap scan on {target} with ports {ports}")
            
            # Perform scan
            scan_result = self.nm.scan(target, ports, arguments=arguments)
            
            if target not in self.nm.all_hosts():
                raise Exception(f"Target {target} not found in scan results")
            
            host_info = self.nm[target]
            
            # Parse results
            results = {
                'target': target,
                'hostname': host_info.hostname(),
                'state': host_info.state(),
                'os_info': self._parse_os_info(host_info),
                'ports': self._parse_ports(host_info),
                'vulnerabilities': self._parse_vulnerabilities(host_info),
                'scan_stats': scan_result.get('nmap', {}).get('scanstats', {})
            }
            
            logger.info(f"Nmap scan completed for {target}")
            return results
            
        except Exception as e:
            logger.error(f"Nmap scan failed for {target}: {str(e)}")
            raise
    
    def _parse_os_info(self, host_info) -> Dict[str, Any]:
        """Parse operating system information from nmap results"""
        os_info = {}
        
        if 'osmatch' in host_info:
            os_matches = host_info['osmatch']
            if os_matches:
                best_match = os_matches[0]
                os_info = {
                    'name': best_match.get('name', 'Unknown'),
                    'accuracy': best_match.get('accuracy', 0),
                    'type': best_match.get('type', 'Unknown')
                }
        
        return os_info
    
    def _parse_ports(self, host_info) -> List[Dict[str, Any]]:
        """Parse open ports from nmap results"""
        ports = []
        
        for protocol in host_info.all_protocols():
            port_list = host_info[protocol].keys()
            for port in port_list:
                port_info = host_info[protocol][port]
                
                port_data = {
                    'port': port,
                    'protocol': protocol,
                    'state': port_info['state'],
                    'service': port_info.get('name', 'unknown'),
                    'version': port_info.get('version', ''),
                    'banner': port_info.get('banner', ''),
                    'product': port_info.get('product', ''),
                    'extrainfo': port_info.get('extrainfo', '')
                }
                ports.append(port_data)
        
        return ports
    
    def _parse_vulnerabilities(self, host_info) -> List[Dict[str, Any]]:
        """Parse vulnerability information from nmap script results"""
        vulnerabilities = []
        
        for protocol in host_info.all_protocols():
            port_list = host_info[protocol].keys()
            for port in port_list:
                port_info = host_info[protocol][port]
                
                # Check for script results
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        if 'vuln' in script_name.lower() or 'cve' in script_name.lower():
                            vuln_data = {
                                'port': port,
                                'protocol': protocol,
                                'script': script_name,
                                'output': script_output,
                                'severity': self._determine_severity(script_output)
                            }
                            vulnerabilities.append(vuln_data)
        
        return vulnerabilities
    
    def _determine_severity(self, script_output: str) -> str:
        """Determine vulnerability severity from script output"""
        output_lower = script_output.lower()
        
        if any(keyword in output_lower for keyword in ['critical', 'high risk', 'exploit']):
            return 'high'
        elif any(keyword in output_lower for keyword in ['medium', 'moderate']):
            return 'medium'
        elif any(keyword in output_lower for keyword in ['low', 'info']):
            return 'low'
        else:
            return 'info'
    
    def save_scan_results(self, scan_id: int, results: Dict[str, Any]) -> None:
        """Save nmap scan results to database"""
        try:
            # Update scan status
            scan = Scan.query.get(scan_id)
            if not scan:
                raise Exception(f"Scan {scan_id} not found")
            
            # Save ports
            for port_data in results.get('ports', []):
                if port_data['state'] == 'open':
                    port = Port(
                        scan_id=scan_id,
                        port_number=port_data['port'],
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        service=port_data['service'],
                        version=port_data['version'],
                        banner=port_data['banner']
                    )
                    db.session.add(port)
            
            db.session.commit()
            logger.info(f"Saved nmap results for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save nmap results for scan {scan_id}: {str(e)}")
            raise
