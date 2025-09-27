"""
Tests for scanning modules
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app.modules.nmap_scanner import NmapScanner
from app.modules.cve_lookup import CVELookup
from app.modules.osint_scanner import OSINTScanner
from app.modules.compliance_checker import ComplianceChecker

class TestNmapScanner:
    """Test NmapScanner class"""
    
    def test_init(self):
        """Test NmapScanner initialization"""
        scanner = NmapScanner()
        assert scanner.nm is not None
    
    @patch('app.modules.nmap_scanner.nmap.PortScanner')
    def test_scan_target_success(self, mock_portscanner):
        """Test successful nmap scan"""
        # Mock nmap results
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {
            'nmap': {
                'scanstats': {'timestr': 'test'}
            }
        }
        mock_scanner.all_hosts.return_value = ['192.168.1.1']
        mock_scanner.__getitem__ = Mock()  # Add __getitem__ support
        
        mock_host = Mock()
        mock_host.hostname.return_value = 'test-host'
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']
        
        # Create a proper mock for tcp ports that supports item assignment
        mock_tcp = {}
        mock_tcp[80] = None  # Will be set later
        mock_tcp[443] = None  # Will be set later
        
        # Configure the host mock to return the tcp dict
        mock_host.__getitem__ = Mock(return_value=mock_tcp)
        
        # Mock port info
        mock_port_info = {
            'state': 'open',
            'name': 'http',
            'version': 'Apache/2.4.41',
            'banner': 'HTTP/1.1 200 OK'
        }
        mock_tcp[80] = mock_port_info
        mock_tcp[443] = mock_port_info
        
        # Configure the scanner to return the host when accessed by IP
        mock_scanner.__getitem__.return_value = mock_host
        mock_portscanner.return_value = mock_scanner
        
        scanner = NmapScanner()
        results = scanner.scan_target('192.168.1.1')
        
        assert results['target'] == '192.168.1.1'
        assert results['hostname'] == 'test-host'
        assert results['state'] == 'up'
        assert len(results['ports']) == 2
    
    @patch('app.modules.nmap_scanner.nmap.PortScanner')
    def test_scan_target_failure(self, mock_portscanner):
        """Test nmap scan failure"""
        mock_scanner = Mock()
        mock_scanner.scan.return_value = {}
        mock_scanner.all_hosts.return_value = []
        mock_portscanner.return_value = mock_scanner
        
        scanner = NmapScanner()
        
        with pytest.raises(Exception):
            scanner.scan_target('192.168.1.1')

class TestCVELookup:
    """Test CVELookup class"""
    
    def test_init(self):
        """Test CVELookup initialization"""
        lookup = CVELookup()
        assert lookup.session is not None
        assert 'User-Agent' in lookup.session.headers
    
    @patch('app.modules.cve_lookup.requests.Session.get')
    def test_lookup_cve_success(self, mock_get):
        """Test successful CVE lookup"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'<html><body><p data-testid="vuln-description">Test vulnerability</p></body></html>'
        mock_get.return_value = mock_response
        
        lookup = CVELookup()
        result = lookup.lookup_cve('CVE-2021-1234')
        
        assert result is not None
        assert result['cve_id'] == 'CVE-2021-1234'
        assert result['source'] == 'NVD'
    
    @patch('app.modules.cve_lookup.requests.Session.get')
    def test_lookup_cve_failure(self, mock_get):
        """Test CVE lookup failure"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        lookup = CVELookup()
        result = lookup.lookup_cve('CVE-2021-1234')
        
        assert result is None
    
    def test_search_cves_by_service(self):
        """Test CVE search by service"""
        lookup = CVELookup()
        
        with patch.object(lookup, '_search_nvd_api') as mock_search:
            mock_search.return_value = [
                {'cve_id': 'CVE-2021-1234', 'description': 'Test CVE'}
            ]
            
            with patch.object(lookup, 'lookup_cve') as mock_lookup:
                mock_lookup.return_value = {
                    'cve_id': 'CVE-2021-1234',
                    'description': 'Test CVE',
                    'severity': 'high'
                }
                
                results = lookup.search_cves_by_service('apache', '2.4.41')
                
                assert len(results) == 1
                assert results[0]['cve_id'] == 'CVE-2021-1234'

class TestOSINTScanner:
    """Test OSINTScanner class"""
    
    def test_init(self):
        """Test OSINTScanner initialization"""
        scanner = OSINTScanner()
        assert scanner.session is not None
        assert 'User-Agent' in scanner.session.headers
    
    @patch('app.modules.osint_scanner.requests.Session.get')
    def test_collect_osint_data(self, mock_get):
        """Test OSINT data collection"""
        # Mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'<html><body><title>Test Page</title></body></html>'
        mock_get.return_value = mock_response
        
        scanner = OSINTScanner()
        
        with patch.object(scanner, '_save_osint_data') as mock_save:
            result = scanner.collect_osint_data('192.168.1.1', 1)
            
            assert result['target'] == '192.168.1.1'
            assert result['scan_id'] == 1
            assert 'shodan_data' in result
            assert 'virustotal_data' in result
    
    def test_extract_shodan_ports(self):
        """Test Shodan port extraction"""
        from bs4 import BeautifulSoup
        
        scanner = OSINTScanner()
        html = '<div class="port">80</div><div class="port">443</div>'
        soup = BeautifulSoup(html, 'html.parser')
        
        ports = scanner._extract_shodan_ports(soup)
        
        assert len(ports) == 2
        assert ports[0]['port'] == 80
        assert ports[1]['port'] == 443

class TestComplianceChecker:
    """Test ComplianceChecker class"""
    
    def test_init(self):
        """Test ComplianceChecker initialization"""
        checker = ComplianceChecker()
        assert checker.nist_controls is not None
        assert 'ID.AM' in checker.nist_controls
        assert 'PR.AC' in checker.nist_controls
    
    def test_categorize_vulnerability(self):
        """Test vulnerability categorization"""
        checker = ComplianceChecker()
        
        # Test SQL injection
        vuln = Mock()
        vuln.title = 'SQL Injection Vulnerability'
        vuln.description = 'SQL injection in login form'
        
        result = checker._categorize_vulnerability(vuln)
        assert result == 'sql_injection'
        
        # Test XSS
        vuln.title = 'Cross-Site Scripting (XSS)'
        vuln.description = 'XSS vulnerability in user input'
        
        result = checker._categorize_vulnerability(vuln)
        assert result == 'xss'
    
    def test_map_vuln_severity_to_compliance(self):
        """Test vulnerability severity mapping"""
        checker = ComplianceChecker()
        
        assert checker._map_vuln_severity_to_compliance('critical') == 'critical'
        assert checker._map_vuln_severity_to_compliance('high') == 'high'
        assert checker._map_vuln_severity_to_compliance('medium') == 'medium'
        assert checker._map_vuln_severity_to_compliance('low') == 'low'
        assert checker._map_vuln_severity_to_compliance('info') == 'low'
    
    def test_get_control_info(self):
        """Test NIST control info retrieval"""
        checker = ComplianceChecker()
        
        info = checker._get_control_info('PR.AC-1')
        assert info is not None
        assert 'title' in info
        assert 'description' in info
        
        # Test non-existent control
        info = checker._get_control_info('INVALID.CONTROL')
        assert info is None
    
    def test_identify_unnecessary_ports(self):
        """Test unnecessary port identification"""
        checker = ComplianceChecker()
        
        # Mock ports
        port1 = Mock()
        port1.port_number = 23  # Telnet
        port1.protocol = 'tcp'
        port1.state = 'open'
        
        port2 = Mock()
        port2.port_number = 80  # HTTP
        port2.protocol = 'tcp'
        port2.state = 'open'
        
        port3 = Mock()
        port3.port_number = 22  # SSH
        port3.protocol = 'tcp'
        port3.state = 'open'
        
        unnecessary = checker._identify_unnecessary_ports([port1, port2, port3])
        
        # Should identify telnet and HTTP as unnecessary
        assert len(unnecessary) == 2
        port_numbers = [item['port'] for item in unnecessary]
        assert 23 in port_numbers  # Telnet
        assert 80 in port_numbers  # HTTP
    
    def test_identify_unencrypted_services(self):
        """Test unencrypted service identification"""
        checker = ComplianceChecker()
        
        # Mock ports
        port1 = Mock()
        port1.port_number = 80
        port1.protocol = 'tcp'
        port1.state = 'open'
        port1.service = 'http'
        
        port2 = Mock()
        port2.port_number = 443
        port2.protocol = 'tcp'
        port2.state = 'open'
        port2.service = 'https'
        
        port3 = Mock()
        port3.port_number = 21
        port3.protocol = 'tcp'
        port3.state = 'open'
        port3.service = 'ftp'
        
        unencrypted = checker._identify_unencrypted_services([port1, port2, port3])
        
        # Should identify HTTP, HTTPS, and FTP as unencrypted
        assert len(unencrypted) == 3
        services = [s['service'] for s in unencrypted]
        assert 'http' in services
        assert 'https' in services
        assert 'ftp' in services
