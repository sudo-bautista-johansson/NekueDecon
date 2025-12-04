import os
import json
import nmap
import socket
import http.server
import socketserver
import webbrowser
import threading
import requests
import ipaddress
import pathlib
import datetime
import logging
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from http import HTTPStatus
import webbrowser
import multiprocessing
import subprocess
import time
import re
import platform
import sys
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from http.server import HTTPServer, SimpleHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import click
import colorama
from colorama import Fore, Style
from jinja2 import Environment, FileSystemLoader
import random
import shutil
import string
import threading
import http.server
import socketserver
from datetime import datetime
from http import HTTPStatus
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin

# Initialize colorama
colorama.init(autoreset=True)

# Version
VERSION = "2.0.0"

# Constants
DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,8080,8443,27017,27018,27019"
OS_FINGERPRINTING_ARGS = "-O --osscan-limit"
STEALTH_SCAN_ARGS = "-sS -T1 -f --data-length 24 --ttl 42 --randomize-hosts --spoof-mac 0"
PASSIVE_DETECTION_ARGS = "-sV --version-intensity 0 --script=banner"
AGGRESSIVE_SCAN_ARGS = "-A -T4 -sV --version-intensity 9 --script=vuln,http-vuln-*,ssl-* --traceroute"
VULN_SCAN_ARGS = "-sV --script=vuln,vulscan/vulscan.nse --script-args vulscandb=exploitdb.csv"
SHODAN_API_URL = "https://api.shodan.io/shodan/host/{}?key={}"
WEB_SERVER_PORT = 8000
DEFAULT_TIMEOUT = 300  # 5 minutes
MAX_WORKERS = multiprocessing.cpu_count() * 2
REPORT_TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORT_OUTPUT_DIR = Path(__file__).parent / "reports"

# Ensure report directories exist
REPORT_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ScanType(Enum):
    """Enumeration of available scan types."""
    QUICK = "quick"                # Fast scan with common ports
    FULL = "full"                  # Comprehensive scan with service detection
    STEALTH = "stealth"            # Stealthy SYN scan
    OS_DETECTION = "os"            # OS detection scan
    PASSIVE = "passive"            # Passive service detection
    AGGRESSIVE = "aggressive"      # Aggressive scan with vulnerability scripts
    VULNERABILITY = "vulnerability" # Vulnerability assessment
    OSINT = "osint"                # Open Source Intelligence gathering
    NETWORK = "network"            # Network discovery scan

@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    name: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    reference: Optional[str] = None
    solution: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    version: Optional[str] = None
    exploit_url: Optional[str] = None

@dataclass
class ScanResult:
    host: str
    ip: str
    hostname: Optional[str] = None
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    os_info: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    shodan_data: Dict[str, Any] = field(default_factory=dict)
    scan_type: Optional[ScanType] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    scan_duration: Optional[float] = None
    is_up: Optional[bool] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    traceroute: List[Dict[str, Any]] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = field(default_factory=lambda: datetime.datetime.now().isoformat())

    # Rest of the class methods remain the same...

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the scan results."""
        self.vulnerabilities.append(vulnerability)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary for JSON serialization."""
        return {
            "host": self.host,
            "ip": self.ip,
            "hostname": self.hostname,
            "open_ports": self.open_ports,
            "os_info": self.os_info,
            "vulnerabilities": [
                {
                    "name": vuln.name,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "cve": vuln.cve,
                    "port": vuln.port,
                    "service": vuln.service,
                    "version": vuln.version,
                    "exploit_url": vuln.exploit_url,
                    "solution": vuln.solution,
                    "reference": vuln.reference
                } for vuln in self.vulnerabilities
            ],
            "shodan_data": self.shodan_data,
            "scan_type": self.scan_type.value if self.scan_type else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scan_duration": self.scan_duration,
            "is_up": self.is_up,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "hostnames": self.hostnames,
            "traceroute": self.traceroute,
            "additional_info": self.additional_info
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Create a ScanResult from a dictionary."""
        result = cls(
            host=data['host'],
            ip=data['ip'],
            hostname=data.get('hostname'),
            open_ports=data.get('open_ports', []),
            os_info=data.get('os_info', {}),
            shodan_data=data.get('shodan_data', {}),
            scan_type=ScanType(data['scan_type']) if data.get('scan_type') else None,
            start_time=datetime.datetime.fromisoformat(data['start_time']) if data.get('start_time') else None,
            end_time=datetime.datetime.fromisoformat(data['end_time']) if data.get('end_time') else None,
            scan_duration=data.get('scan_duration'),
            is_up=data.get('is_up'),
            mac_address=data.get('mac_address'),
            vendor=data.get('vendor'),
            hostnames=data.get('hostnames', []),
            traceroute=data.get('traceroute', []),
            additional_info=data.get('additional_info', {})
        )
        
        # Add vulnerabilities
        for vuln_data in data.get('vulnerabilities', []):
            result.add_vulnerability(Vulnerability(
                name=vuln_data['name'],
                description=vuln_data['description'],
                severity=vuln_data['severity'],
                cvss_score=vuln_data.get('cvss_score'),
                cve=vuln_data.get('cve'),
                port=vuln_data.get('port'),
                service=vuln_data.get('service'),
                solution=vuln_data.get('solution'),
                reference=vuln_data.get('reference')
            ))
            
        return result

class HTMLReportGenerator:
    """Generates professional HTML reports from scan results."""
    
    def __init__(self, output_dir: Path = None):
        """Initialize the HTML report generator.
        
        Args:
            output_dir: Directory to save the generated reports
        """
        self.output_dir = output_dir or REPORT_OUTPUT_DIR
        self.template_dir = REPORT_TEMPLATE_DIR
        self._ensure_templates_exist()
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        
    def _ensure_templates_exist(self) -> None:
        """Ensure that all required template files exist."""
        templates = {
            'report.html': """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Scan Report - {{ scan_type|capitalize }} Scan</title>
                <style>
                    /* Add your CSS styles here */
                    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }
                    .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
                    .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    .vulnerability { margin-bottom: 15px; padding: 10px; border-left: 4px solid #e74c3c; }
                    .critical { border-color: #e74c3c; }
                    .high { border-color: #e67e22; }
                    .medium { border-color: #f39c12; }
                    .low { border-color: #3498db; }
                    .info { border-color: #2ecc71; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #f2f2f2; }
                    tr:hover { background-color: #f5f5f5; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Network Scan Report</h1>
                    <p>Generated on: {{ timestamp }}</p>
                </div>
                
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p><strong>Scan Type:</strong> {{ scan_type|capitalize }}</p>
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Start Time:</strong> {{ start_time }}</p>
                    <p><strong>End Time:</strong> {{ end_time }}</p>
                    <p><strong>Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Hosts Scanned:</strong> {{ results|length }}</p>
                    <p><strong>Vulnerabilities Found:</strong> {{ vulnerabilities|length }}</p>
                </div>
                
                {% for result in results %}
                <div class="host-section">
                    <h2>Host: {{ result.host }} ({{ result.ip }})</h2>
                    {% if result.hostname %}<p><strong>Hostname:</strong> {{ result.hostname }}</p>{% endif %}
                    {% if result.mac_address %}<p><strong>MAC Address:</strong> {{ result.mac_address }}</p>{% endif %}
                    {% if result.vendor %}<p><strong>Vendor:</strong> {{ result.vendor }}</p>{% endif %}
                    
                    {% if result.os_info %}
                    <h3>Operating System</h3>
                    <p>{{ result.os_info.get('name', 'Unknown') }} ({{ result.os_info.get('accuracy', 'N/A') }}% confidence)</p>
                    {% endif %}
                    
                    {% if result.open_ports %}
                    <h3>Open Ports ({{ result.open_ports|length }})</h3>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>State</th>
                        </tr>
                        {% for port in result.open_ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.version or 'N/A' }}</td>
                            <td>{{ port.state }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if result.vulnerabilities %}
                    <h3>Vulnerabilities ({{ result.vulnerabilities|length }})</h3>
                    {% for vuln in result.vulnerabilities %}
                    <div class="vulnerability {{ vuln.severity|lower }}">
                        <h4>{{ vuln.name }}</h4>
                        <p><strong>Severity:</strong> {{ vuln.severity|upper }} 
                        {% if vuln.cvss_score %}(CVSS: {{ "%.1f"|format(vuln.cvss_score) }}){% endif %}</p>
                        <p><strong>Port:</strong> {{ vuln.port or 'N/A' }} / <strong>Service:</strong> {{ vuln.service or 'N/A' }}</p>
                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                        {% if vuln.solution %}<p><strong>Solution:</strong> {{ vuln.solution }}</p>{% endif %}
                        {% if vuln.reference %}<p><strong>Reference:</strong> {{ vuln.reference }}</p>{% endif %}
                    </div>
                    {% endfor %}
                    {% endif %}
                </div>
                <hr>
                {% endfor %}
                
                <div class="footer">
                    <p>Report generated by Network Scanner v{{ version }}</p>
                </div>
            </body>
            </html>
            """
        }
        
        # Create template directory if it doesn't exist
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Create default templates if they don't exist
        for filename, content in templates.items():
            template_path = self.template_dir / filename
            if not template_path.exists():
                with open(template_path, 'w') as f:
                    f.write(content)
    
    def generate_report(self, results: Union[ScanResult, List[ScanResult]], 
                       scan_type: str, target: str) -> Path:
        """Generate an HTML report from scan results.
        
        Args:
            results: Single ScanResult or list of ScanResult objects
            scan_type: Type of scan that was performed
            target: Target that was scanned
            
        Returns:
            Path to the generated HTML report
        """
        if not isinstance(results, list):
            results = [results]
            
        # Prepare data for template
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_time = min(r.start_time for r in results if r.start_time)
        end_time = max(r.end_time for r in results if r.end_time)
        duration = sum((r.scan_duration or 0) for r in results)
        
        # Flatten all vulnerabilities
        all_vulnerabilities = []
        for result in results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        # Sort vulnerabilities by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_vulnerabilities.sort(key=lambda x: severity_order.get(x.severity.lower(), 99))
        
        # Prepare context for template
        context = {
            'version': VERSION,
            'timestamp': timestamp,
            'scan_type': scan_type,
            'target': target,
            'start_time': start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else 'N/A',
            'end_time': end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else 'N/A',
            'duration': f"{duration:.2f}",
            'results': [r.to_dict() for r in results],
            'vulnerabilities': [{
                'name': v.name,
                'severity': v.severity,
                'cvss_score': v.cvss_score,
                'port': v.port,
                'service': v.service,
                'description': v.description,
                'solution': v.solution,
                'reference': v.reference
            } for v in all_vulnerabilities]
        }
        
        # Render template
        template = self.env.get_template('report.html')
        html_content = template.render(**context)
        
        # Save report
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.output_dir / f"scan_report_{int(time.time())}.html"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return report_path

class AdvancedNmapScanner:
    """Advanced Nmap scanner with vulnerability detection and reporting."""
    
    def __init__(self, shodan_api_key: str = None, output_dir: Path = None):
        """Initialize the Nmap scanner.
        
        Args:
            shodan_api_key: Optional Shodan API key for OSINT
            output_dir: Directory to save scan results and reports
        """
        self.shodan_api_key = shodan_api_key
        self.output_dir = output_dir or Path.cwd() / "scan_results"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize logger first
        self.logger = logging.getLogger(__name__)
        # Configure basic logging if not already configured
        if not logging.getLogger().hasHandlers():
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        # Initialize Nmap
        self.nm = nmap.PortScanner()
        self._check_nmap_installation()
        
        # Initialize report generator
        self.report_generator = HTMLReportGenerator(self.output_dir)
        
    def _check_nmap_installation(self) -> None:
        """Check if Nmap is installed and accessible."""
        try:
            nmap_path = self._find_nmap()
            if not nmap_path:
                raise RuntimeError("Nmap not found. Please install Nmap and ensure it's in your PATH.")
            self.nm_path = nmap_path
            self.logger.info(f"Using Nmap from: {nmap_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize Nmap: {e}")
            raise
            
    def _find_nmap(self) -> Optional[str]:
        """Find Nmap executable path.
        
        Returns:
            Path to Nmap executable or None if not found
        """
        # Common Nmap paths
        nmap_paths = [
            "nmap",  # In PATH
            "/usr/bin/nmap",  # Linux
            "/usr/local/bin/nmap",  # Mac/Linux
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",  # Windows 64-bit
            "C:\\Program Files\\Nmap\\nmap.exe",  # Windows 32-bit
        ]
        
        for path in nmap_paths:
            try:
                if subprocess.run([path, "--version"], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE).returncode == 0:
                    return path
            except (FileNotFoundError, OSError):
                continue
                
        return None
        
    def scan_network(self, target: str, scan_type: ScanType = ScanType.QUICK, 
                    ports: str = None, timeout: int = None, 
                    max_workers: int = None) -> List[ScanResult]:
        """Scan a network range or a list of hosts.
        
        Args:
            target: IP address, hostname, or CIDR range to scan
            scan_type: Type of scan to perform
            ports: Ports to scan (e.g., "80,443,8080" or "1-1024")
            timeout: Maximum time to wait for scan to complete (in seconds)
            max_workers: Maximum number of concurrent scans
            
        Returns:
            List of ScanResult objects
        """
        self.logger.info(f"Starting {scan_type.value} scan of {target}")
        
        # Set default values
        ports = ports or DEFAULT_PORTS
        timeout = timeout or DEFAULT_TIMEOUT
        max_workers = max_workers or MAX_WORKERS
        
        # Determine if target is a single host or network range
        try:
            # Try to parse as IP network
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(host) for host in network.hosts()]
            self.logger.info(f"Scanning network {target} with {len(hosts)} hosts")
        except ValueError:
            # Not a network, treat as single host or hostname
            hosts = [target]
            
        # Scan hosts in parallel
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan_host, host, scan_type, ports, timeout): host 
                for host in hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.logger.info(f"Completed scan of {host}: {len(result.open_ports)} open ports, {len(result.vulnerabilities)} vulnerabilities")
                    else:
                        self.logger.warning(f"Scan of {host} returned no results")
                except Exception as e:
                    self.logger.error(f"Error scanning {host}: {e}")
                    
        return results
        
    def scan_host(self, host: str, shodan_key: Optional[str] = None) -> ScanResult:
        try:
        
            return self._parse_scan_results(host, shodan_key)
        except Exception as e:
            logging.error(f"Error al escanear {host}: {str(e)}")
            return ScanResult(host=host, ip=socket.gethostbyname(host), open_ports=[])
        """Scan a single host.
        
        Args:
            host: Hostname or IP address to scan
            scan_type: Type of scan to perform
            ports: Ports to scan (e.g., "80,443,8080" or "1-1024")
            timeout: Maximum time to wait for scan to complete (in seconds)
            
        Returns:
            ScanResult object or None if scan fails
        """
        self.logger.info(f"Starting {scan_type.value} scan of {host}")
        
        # Set default values
        ports = ports or DEFAULT_PORTS
        timeout = timeout or DEFAULT_TIMEOUT
        
        # Initialize result
        result = ScanResult(
            host=host,
            ip=socket.gethostbyname(host) if not self._is_ip(host) else host,
            scan_type=scan_type,
            start_time=datetime.datetime.now()
        )
        
        try:
            # Determine Nmap arguments based on scan type
            nmap_args = self._get_nmap_arguments(scan_type, ports)
            
            # Run the scan
            self.logger.debug(f"Running Nmap with arguments: {nmap_args}")
            scan_result = self.nm.scan(hosts=host, arguments=nmap_args, timeout=timeout * 60)
            
            # Process the results
            if host in scan_result['scan']:
                host_result = scan_result['scan'][host]
                result = self._parse_scan_results(host_result, result)
                
                # Perform additional scans based on scan type
                if scan_type in [ScanType.FULL, ScanType.AGGRESSIVE, ScanType.VULNERABILITY]:
                    result = self._scan_for_vulnerabilities(result)
                
                if scan_type in [ScanType.OSINT, ScanType.FULL] and self.shodan_api_key:
                    result = self._osint_scan(result)
                
                # Update scan completion time
                result.end_time = datetime.datetime.now()
                result.scan_duration = (result.end_time - result.start_time).total_seconds()
                
                return result
            else:
                self.logger.warning(f"No scan results for host: {host}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error scanning {host}: {e}")
            result.end_time = datetime.datetime.now()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            return result
            
    def _get_nmap_arguments(self, scan_type: ScanType, ports: str) -> str:
        """Get Nmap arguments for the specified scan type.
        
        Args:
            scan_type: Type of scan to perform
            ports: Ports to scan
            
        Returns:
            Nmap command line arguments as a string
        """
        base_args = f"-p {ports}"
        
        if scan_type == ScanType.QUICK:
            return f"{base_args} -T4 -F"
        elif scan_type == ScanType.FULL:
            return f"{base_args} -A -T4 -sV -O --traceroute"
        elif scan_type == ScanType.STEALTH:
            return f"{base_args} {STEALTH_SCAN_ARGS}"
        elif scan_type == ScanType.OS_DETECTION:
            return f"{base_args} {OS_FINGERPRINTING_ARGS}"
        elif scan_type == ScanType.PASSIVE:
            return f"{base_args} {PASSIVE_DETECTION_ARGS}"
        elif scan_type == ScanType.AGGRESSIVE:
            return f"{base_args} {AGGRESSIVE_SCAN_ARGS}"
        elif scan_type == ScanType.VULNERABILITY:
            return f"{base_args} {VULN_SCAN_ARGS}"
        elif scan_type == ScanType.OSINT:
            return f"{base_args} -sV --script=banner"
        elif scan_type == ScanType.NETWORK:
            return f"-sn"  # Ping scan only
        else:
            return base_args  # Default to quick scan
            
    def _parse_scan_results(self, host_result: Dict, result: ScanResult) -> ScanResult:
        """Parse Nmap scan results into a ScanResult object.
        
        Args:
            host_result: Raw Nmap host scan result
            result: ScanResult object to update
            
        Returns:
            Updated ScanResult object
        """
        # Basic host information
        result.is_up = host_result.get('status', {}).get('state') == 'up'
        
        # MAC address and vendor
        if 'mac' in host_result.get('addresses', {}):
            result.mac_address = host_result['addresses']['mac']
            if 'vendor' in host_result and result.mac_address in host_result['vendor']:
                result.vendor = host_result['vendor'][result.mac_address]
        
        # Hostnames
        if 'hostnames' in host_result:
            result.hostnames = [h['name'] for h in host_result['hostnames'] if h['name']]
            if result.hostnames and not result.hostname:
                result.hostname = result.hostnames[0]
        
        # OS information
        if 'osmatch' in host_result:
            os_matches = host_result['osmatch']
            if os_matches:
                best_os = max(os_matches, key=lambda x: float(x.get('accuracy', 0)))
                result.os_info = {
                    'name': best_os.get('name', 'Unknown'),
                    'accuracy': float(best_os.get('accuracy', 0)),
                    'osclass': [{
                        'type': c.get('type', ''),
                        'vendor': c.get('vendor', ''),
                        'osfamily': c.get('osfamily', ''),
                        'osgen': c.get('osgen', ''),
                        'accuracy': int(c.get('accuracy', 0))
                    } for c in best_os.get('osclass', [])]
                }
        
        # Open ports and services
        if 'tcp' in host_result:
            for port, port_info in host_result['tcp'].items():
                if port_info['state'] == 'open':
                    result.open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'state': port_info['state'],
                        'reason': port_info.get('reason', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'conf': port_info.get('conf', ''),
                        'cpe': port_info.get('cpe', '')
                    })
        
        # UDP ports (if any)
        if 'udp' in host_result:
            for port, port_info in host_result['udp'].items():
                if port_info['state'] == 'open':
                    result.open_ports.append({
                        'port': port,
                        'protocol': 'udp',
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'state': port_info['state'],
                        'reason': port_info.get('reason', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'conf': port_info.get('conf', ''),
                        'cpe': port_info.get('cpe', '')
                    })
        
        # Sort ports by number
        open_ports.sort(key=lambda x: x['port'])
    
        return ScanResult(
            host=host,
            ip=ip,
            hostname=hostname,
            open_ports=open_ports,
            os_info=os_info,
            vulnerabilities=vulnerabilities,
            shodan_data=shodan_data,
            mac_address=mac_address,
            vendor=vendor,
            hostnames=hostnames,
            is_up=is_up,
            scan_type=self.scan_type
    )
    
        return result
        
    def _scan_for_vulnerabilities(self, result: ScanResult) -> ScanResult:
        """Scan for vulnerabilities on open ports.
        
        Args:
            result: ScanResult object with open ports
            
        Returns:
            Updated ScanResult with vulnerabilities
        """
        if not result.open_ports:
            return result
            
        self.logger.info(f"Scanning for vulnerabilities on {result.host}")
        
        # Check each open port for known vulnerabilities
        for port_info in result.open_ports:
            # Skip if we already have vulnerability info from NSE scripts
            if 'script' in port_info and 'vuln' in port_info['script']:
                continue
                
            # Check for known vulnerabilities based on service/version
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '').lower()
            cpe = port_info.get('cpe', '')
            
            # Example vulnerability checks (in a real implementation, this would use a vulnerability database)
            if 'apache' in service and '2.4.49' in version:
                result.add_vulnerability(Vulnerability(
                    name="Apache HTTP Server Path Traversal (CVE-2021-41773)",
                    description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
                    severity="Critical",
                    cvss_score=9.8,
                    cve="CVE-2021-41773",
                    port=port_info['port'],
                    service=service,
                    version=version,
                    exploit_url="https://www.exploit-db.com/exploits/50383",
                    solution="Upgrade to Apache HTTP Server 2.4.50 or later.",
                    reference="https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                ))
            # Add more vulnerability checks here...
            
        return result
        
    def _osint_scan(self, result: ScanResult) -> ScanResult:
        """Perform OSINT gathering for the target.
        
        Args:
            result: ScanResult object to update with OSINT data
            
        Returns:
            Updated ScanResult object
        """
        if not self.shodan_api_key:
            self.logger.warning("No Shodan API key provided, skipping OSINT scan")
            return result
            
        self.logger.info(f"Performing OSINT scan for {result.ip}")
        
        try:
            shodan_data = self._get_shodan_info(result.ip)
            if shodan_data:
                result.shodan_data = shodan_data
                self.logger.info(f"Found {len(shodan_data.get('data', []))} Shodan records for {result.ip}")
        except Exception as e:
            self.logger.error(f"Error during OSINT scan: {e}")
            
        return result
        
    def _get_shodan_info(self, ip: str) -> Optional[Dict]:
        """Get information about an IP from Shodan.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Dictionary containing Shodan data or None if not found
        """
        if not self.shodan_api_key:
            return None
            
        try:
            url = SHODAN_API_URL.format(ip, self.shodan_api_key)
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"Error querying Shodan: {e}")
            return None
            
    def _is_ip(self, address: str) -> bool:
        """Check if a string is an IP address.
        
        Args:
            address: String to check
            
        Returns:
            True if the string is an IP address, False otherwise
                    </div>
                </div>
        import socketserver
        import webbrowser
        import threading
        import functools
        
        handler = functools.partial(self.RequestHandler, self)
        
        class Server(socketserver.TCPServer):
            allow_reuse_address = True
        
        try:
            with Server(('0.0.0.0', self.port), handler) as httpd:
                self.server = httpd
                print(f"Servidor web iniciado en http://localhost:{self.port}")
                webbrowser.open(f"http://localhost:{self.port}")
                httpd.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"Error: El puerto {self.port} ya está en uso. Por favor, cierra cualquier otra instancia del servidor.")
            else:
                print(f"Error al iniciar el servidor: {e}")
        except KeyboardInterrupt:
            print("\nDeteniendo el servidor...")
            if hasattr(self, 'server'):
                self.server.shutdown()
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                .host-card {{ transition: all 0.3s ease; }}
                .host-card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }}
                .vuln-critical {{ border-left: 4px solid #dc2626; }}
                .vuln-high {{ border-left: 4px solid #ea580c; }}
                .vuln-medium {{ border-left: 4px solid #d97706; }}
                .vuln-low {{ border-left: 4px solid #65a30d; }}
                .vuln-info {{ border-left: 4px solid #0891b2; }}
                .port-badge {{ transition: all 0.2s; }}
                .port-badge:hover {{ transform: scale(1.05); }}
                .fade-in {{ animation: fadeIn 0.5s; }}
                @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
            </style>
        </head>
        <body class="bg-gray-50">
            <header class="bg-blue-600 text-white shadow-lg">
                <div class="container mx-auto px-6 py-4">
                    <div class="flex items-center justify-between">
                        <h1 class="text-2xl font-bold"><i class="fas fa-shield-alt mr-2"></i>Network Scanner Pro</h1>
                        <div class="text-sm">
                            <span id="current-time" class="bg-blue-700 px-3 py-1 rounded-full"></span>
                        </div>
                    </div>
                </div>
            </header>

            <main class="container mx-auto px-4 py-6">
                <!-- Summary Cards -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div class="bg-white rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="p-3 rounded-full bg-blue-100 text-blue-600 mr-4">
                                <i class="fas fa-laptop-house text-xl"></i>
                            </div>
                            <div>
                                <p class="text-gray-500 text-sm">Hosts Escaneados</p>
                                <p class="text-2xl font-bold" id="total-hosts">{len(self.results)}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="p-3 rounded-full bg-green-100 text-green-600 mr-4">
                                <i class="fas fa-plug text-xl"></i>
                            </div>
                            <div>
                                <p class="text-gray-500 text-sm">Puertos Abiertos</p>
                                <p class="text-2xl font-bold" id="total-ports">{sum(len(host.open_ports) for host in self.results)}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="p-3 rounded-full bg-red-100 text-red-600 mr-4">
                                <i class="fas fa-bug text-xl"></i>
                            </div>
                            <div>
                                <p class="text-gray-500 text-sm">Vulnerabilidades</p>
                                <p class="text-2xl font-bold" id="total-vulns">{sum(len(host.vulnerabilities) for host in self.results)}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-white rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="p-3 rounded-full bg-yellow-100 text-yellow-600 mr-4">
                                <i class="fas fa-shield-alt text-xl"></i>
                            </div>
                            <div>
                                <p class="text-gray-500 text-sm">Nivel de Riesgo</p>
                                <p class="text-2xl font-bold" id="risk-level">{self._calculate_risk_level()}</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Hosts Section -->
                <div class="bg-white rounded-lg shadow overflow-hidden mb-8">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h2 class="text-xl font-semibold text-gray-800">Hosts Escaneados</h2>
                    </div>
                    <div class="divide-y divide-gray-200" id="hosts-container">
                        {"".join(self._generate_host_card(host) for host in self.results)}
                    </div>
                </div>
            </main>

            <footer class="bg-gray-800 text-white py-6">
                <div class="container mx-auto px-6 text-center">
                    <p>Generado con Network Scanner Pro - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </footer>

            <script>
                // Update current time
                function updateTime() {{
                    const now = new Date();
                    document.getElementById('current-time').textContent = 
                        `${{now.toLocaleDateString()}} ${{now.toLocaleTimeString()}}`;
                }}
                updateTime();
                setInterval(updateTime, 1000);

                // Toggle host details
                document.querySelectorAll('.toggle-details').forEach(button => {{
                    button.addEventListener('click', function() {{
                        const details = this.closest('.host-card').querySelector('.host-details');
                        details.classList.toggle('hidden');
                        const icon = this.querySelector('i');
                        icon.classList.toggle('fa-chevron-down');
                        icon.classList.toggle('fa-chevron-up');
                    }});
                }});
            </script>
        </body>
        </html>
        """

    def _generate_host_card(self, host: ScanResult) -> str:
        """Generate HTML for a single host card."""
        vuln_count = len(host.vulnerabilities)
        return f"""
        <div class="host-card bg-white p-6 rounded-lg shadow-md mb-4">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-semibold text-gray-800 flex items-center">
                        <i class="fas fa-laptop mr-2 text-blue-600"></i>
                        {host.host} {f'({host.hostname})' if host.hostname else ''}
                    </h3>
                    <div class="flex flex-wrap gap-2 mt-2">
                        <span class="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full">
                            <i class="fas fa-ip-address mr-1"></i> {host.ip}
                        </span>
                        {f'<span class="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded-full"><i class="fas fa-ethernet mr-1"></i> {host.mac_address}</span>' if host.mac_address else ''}
                        {f'<span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full"><i class="fas fa-microchip mr-1"></i> {host.os_info.get("name", "Sistema operativo no detectado")}</span>' if host.os_info else ''}
                    </div>
                </div>
                <div class="text-right">
                    <span class="inline-block bg-gray-100 text-gray-800 text-sm px-3 py-1 rounded-full">
                        {len(host.open_ports)} puerto{'s' if len(host.open_ports) != 1 else ''} abierto{'s' if len(host.open_ports) != 1 else ''}
                    </span>
                    {f'<span class="ml-2 inline-block bg-red-100 text-red-800 text-sm px-3 py-1 rounded-full">{vuln_count} vulnerabilidad{"es" if vuln_count != 1 else ""}</span>' if vuln_count > 0 else ''}
                </div>
            </div>
            
            <div class="mt-4 border-t pt-4">
                <button class="toggle-details text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center">
                    <i class="fas fa-chevron-down mr-1 text-xs"></i> Ver detalles
                </button>
                
                <div class="host-details hidden mt-4">
                    <h4 class="font-medium text-gray-700 mb-2">Puertos Abiertos:</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {self._generate_port_cards(host)}
                    </div>
                    
                    {self._generate_vulnerability_section(host) if vuln_count > 0 else ''}
                    
                    {self._generate_shodan_section(host) if hasattr(host, 'shodan_data') and host.shodan_data else ''}
                </div>
            </div>
        </div>
        """

    def _generate_port_cards(self, host: ScanResult) -> str:
        """Generate HTML for port cards."""
        return "".join(f"""
        <div class="port-badge border rounded p-3 hover:shadow-md transition-shadow">
            <div class="flex justify-between items-center">
                <span class="font-mono font-bold text-blue-600">Puerto {port['port']}/{port.get('protocol', 'tcp')}</span>
                <span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">Abierto</span>
            </div>
            <div class="mt-2 text-sm">
                <p><span class="text-gray-500">Servicio:</span> {port.get('service', 'desconocido')}</p>
                {f'<p><span class="text-gray-500">Versión:</span> {port["version"]}</p>' if port.get('version') else ''}
                {f'<p><span class="text-gray-500">Producto:</span> {port["product"]}</p>' if port.get('product') else ''}
                {f'<p class="mt-1"><span class="text-gray-500">CPE:</span> <span class="text-xs font-mono bg-gray-100 p-1 rounded">{port["cpe"]}</span></p>' if port.get('cpe') else ''}
            </div>
        </div>
        """ for port in host.open_ports)

    def _generate_vulnerability_section(self, host: ScanResult) -> str:
        """Generate HTML for vulnerabilities section."""
        return f"""
        <div class="mt-6">
            <h4 class="font-medium text-gray-700 mb-3">Vulnerabilidades:</h4>
            <div class="space-y-3">
                {"".join(self._generate_vulnerability_card(vuln) for vuln in host.vulnerabilities)}
            </div>
        </div>
        """

    def _generate_vulnerability_card(self, vuln: Vulnerability) -> str:
        """Generate HTML for a single vulnerability."""
        severity_class = f"vuln-{vuln.severity.lower()}" if hasattr(vuln, 'severity') else "vuln-info"
        severity_text = getattr(vuln, 'severity', 'info').capitalize()
        
        return f"""
        <div class="p-4 rounded-md bg-white border-l-4 {severity_class} shadow-sm">
            <div class="flex justify-between items-start">
                <div>
                    <h5 class="font-semibold text-gray-800">{getattr(vuln, 'name', 'Vulnerabilidad')}</h5>
                    <div class="flex items-center mt-1">
                        <span class="px-2 py-0.5 text-xs rounded-full 
                            {'bg-red-100 text-red-800' if severity_text.lower() == 'critical' else
                             'bg-orange-100 text-orange-800' if severity_text.lower() == 'high' else
                             'bg-yellow-100 text-yellow-800' if severity_text.lower() == 'medium' else
                             'bg-green-100 text-green-800' if severity_text.lower() == 'low' else
                             'bg-blue-100 text-blue-800'}">
                            {severity_text}
                            {f' (CVSS: {vuln.cvss_score})' if hasattr(vuln, 'cvss_score') and vuln.cvss_score else ''}
                        </span>
                        {f'<span class="ml-2 px-2 py-0.5 bg-gray-100 text-gray-800 text-xs rounded-full">Puerto: {vuln.port}/{vuln.service}</span>' if hasattr(vuln, 'port') and hasattr(vuln, 'service') and vuln.port and vuln.service else ''}
                    </div>
                </div>
                {f'<a href="{vuln.reference}" target="_blank" class="text-blue-600 hover:text-blue-800 text-sm"><i class="fas fa-external-link-alt"></i> Referencia</a>' if hasattr(vuln, 'reference') and vuln.reference else ''}
            </div>
            <p class="mt-2 text-sm text-gray-700">{getattr(vuln, 'description', 'No hay descripción disponible.')}</p>
            {f'<div class="mt-2 p-2 bg-yellow-50 text-yellow-800 text-sm rounded border border-yellow-200"><strong>Solución:</strong> {vuln.solution}</div>' if hasattr(vuln, 'solution') and vuln.solution else ''}
        </div>
        """

    def _generate_shodan_section(self, host: ScanResult) -> str:
        """Generate HTML for Shodan OSINT data."""
        if not hasattr(host, 'shodan_data') or not host.shodan_data:
            return ""
            
        data = host.shodan_data
        return f"""
        <div class="mt-6">
            <h4 class="font-medium text-gray-700 mb-3">Información de Shodan:</h4>
            <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
                {f'<p class="mb-2"><span class="font-medium">Organización:</span> {data.get("org", "N/A")}</p>' if data.get("org") else ''}
                {f'<p class="mb-2"><span class="font-medium">Sistema operativo:</span> {data.get("os", "N/A")}</p>' if data.get("os") else ''}
                {f'<p class="mb-2"><span class="font-medium">Puertos abiertos:</span> {", ".join(map(str, data.get("ports", [])))}</p>' if data.get("ports") else ''}
                {f'<p class="mb-2"><span class="font-medium">Hostnames:</span> {", ".join(data.get("hostnames", []))}</p>' if data.get("hostnames") else ''}
                {f'<p class="mb-2"><span class="font-medium">Última actualización:</span> {data.get("last_update", "N/A")}</p>' if data.get("last_update") else ''}
            </div>
        </div>
        """

    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level based on vulnerabilities."""
        if not self.results:
            return "Bajo"
        
        def do_GET(self):
            if self.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self.generate_html().encode('utf-8'))
            else:
                return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        def generate_html(self) -> str:
            """Generate the HTML dashboard with scan results."""
            import html as html_escape
            from datetime import datetime
            
            # Calculate metrics
            host_count = len(self.dashboard.results)
            port_count = sum(len(host.open_ports) for host in self.dashboard.results)
            vuln_count = sum(len(host.vulnerabilities) for host in self.dashboard.results)
            risk_level = self._calculate_risk_level()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Start building HTML with f-strings for better readability and safety
            html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Escaneo de Red</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .host-card {{ transition: all 0.3s ease; }}
        .host-card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }}
        .vuln-critical {{ border-left: 4px solid #dc2626; }}
        .vuln-high {{ border-left: 4px solid #ea580c; }}
        .vuln-medium {{ border-left: 4px solid #d97706; }}
        .vuln-low {{ border-left: 4px solid #65a30d; }}
        .vuln-info {{ border-left: 4px solid #0891b2; }}
        .port-badge {{ transition: all 0.2s; }}
        .port-badge:hover {{ transform: scale(1.05); }}
        .fade-in {{ animation: fadeIn 0.5s; }}
        @keyframes fadeIn {{ 
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
    </style>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <header class="bg-blue-600 text-white shadow-lg">
            <div class="container mx-auto px-6 py-4">
                <div class="flex items-center justify-between">
                    <h1 class="text-2xl font-bold"><i class="fas fa-shield-alt mr-2"></i>Network Scanner Pro</h1>
                    <div class="text-sm">
                        <span id="current-time" class="bg-blue-700 px-3 py-1 rounded-full">{timestamp}</span>
                    </div>
                </div>
            </div>
        </header>

        <main class="container mx-auto px-4 py-6">
            <!-- Summary Cards -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-blue-100 text-blue-600 mr-4">
                            <i class="fas fa-laptop-house text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Hosts Escaneados</p>
                            <p class="text-2xl font-bold" id="total-hosts">{host_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-green-100 text-green-600 mr-4">
                            <i class="fas fa-plug text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Puertos Abiertos</p>
                            <p class="text-2xl font-bold" id="total-ports">{port_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-red-100 text-red-600 mr-4">
                            <i class="fas fa-bug text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Vulnerabilidades</p>
                            <p class="text-2xl font-bold" id="total-vulns">{vuln_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-3 rounded-full bg-yellow-100 text-yellow-600 mr-4">
                            <i class="fas fa-shield-alt text-xl"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Nivel de Riesgo</p>
                            <p class="text-2xl font-bold" id="risk-level">{risk_level}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="space-y-6">
"""
            
            # Add host cards with proper escaping
            for host in self.dashboard.results:
                html += self._generate_host_card(host)
            
            # Close HTML
            html += """
                        </div>
                    </main>

                    <footer class="bg-gray-800 text-white py-6">
                        <div class="container mx-auto px-6 text-center">
                            <p>Generado con Network Scanner Pro - """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                        </div>
                    </footer>
                </div>

                <script>
                    // Update current time
                    function updateTime() {
                        const now = new Date();
                        document.getElementById('current-time').textContent = 
                            `${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;
                    }
                    updateTime();
                    setInterval(updateTime, 1000);

                    // Toggle host details
                    document.querySelectorAll('.toggle-details').forEach(button => {
                        button.addEventListener('click', function() {
                            const details = this.closest('.host-card').querySelector('.host-details');
                            details.classList.toggle('hidden');
                            const icon = this.querySelector('i');
                            icon.classList.toggle('fa-chevron-down');
                            icon.classList.toggle('fa-chevron-up');
                        });
                    });
                </script>
            </body>
            </html>
            """
            return html
            
        def _generate_host_card(self, host):
            """Generate HTML for a single host card."""
            vuln_count = len(host.vulnerabilities)
            return f"""
            <div class="host-card bg-white p-6 rounded-lg shadow-md mb-4">
                <div class="flex justify-between items-center">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-800 flex items-center">
                            <i class="fas fa-laptop mr-2 text-blue-600"></i>
                            {host.host} {f'({host.hostname})' if hasattr(host, 'hostname') and host.hostname else ''}
                        </h3>
                        <div class="flex flex-wrap gap-2 mt-2">
                            <span class="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full">
                                <i class="fas fa-ip-address mr-1"></i> {host.ip}
                            </span>
                            {f'<span class="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded-full"><i class="fas fa-ethernet mr-1"></i> {host.mac_address}</span>' if hasattr(host, 'mac_address') and host.mac_address else ''}
                            {f'<span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full"><i class="fas fa-microchip mr-1"></i> {host.os_info.get("name", "Sistema operativo no detectado")}</span>' if hasattr(host, 'os_info') and host.os_info else ''}
                        </div>
                    </div>
                    <div class="text-right">
                        <span class="inline-block bg-gray-100 text-gray-800 text-sm px-3 py-1 rounded-full">
                            {len(host.open_ports)} puerto{'s' if len(host.open_ports) != 1 else ''} abierto{'s' if len(host.open_ports) != 1 else ''}
                        </span>
                        {f'<span class="ml-2 inline-block bg-red-100 text-red-800 text-sm px-3 py-1 rounded-full">{vuln_count} vulnerabilidad{"es" if vuln_count != 1 else ""}</span>' if vuln_count > 0 else ''}
                    </div>
                </div>
                
                <div class="mt-4 border-t pt-4">
                    <button class="toggle-details text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center">
                        <i class="fas fa-chevron-down mr-1 text-xs"></i> Ver detalles
                    </button>
                    
                    <div class="host-details hidden mt-4">
                        <h4 class="font-medium text-gray-700 mb-2">Puertos Abiertos:</h4>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {self._generate_port_cards(host)}
                        </div>
                        
                        {self._generate_vulnerability_section(host) if vuln_count > 0 else ''}
                    </div>
                </div>
            </div>
            """
            
        def _generate_port_cards(self, host):
            """Generate HTML for port cards."""
            return "".join(f"""
            <div class="port-badge border rounded p-3 hover:shadow-md transition-shadow">
                <div class="flex justify-between items-center">
                    <span class="font-mono font-bold text-blue-600">Puerto {port.get('port', '')}/{port.get('protocol', 'tcp')}</span>
                    <span class="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">Abierto</span>
                </div>
                <div class="mt-2 text-sm">
                    <p><span class="text-gray-500">Servicio:</span> {port.get('service', 'desconocido')}</p>
                    {f'<p><span class="text-gray-500">Versión:</span> {port["version"]}</p>' if port.get('version') else ''}
                    {f'<p><span class="text-gray-500">Producto:</span> {port["product"]}</p>' if port.get('product') else ''}
                    {f'<p class="mt-1"><span class="text-gray-500">CPE:</span> <span class="text-xs font-mono bg-gray-100 p-1 rounded">{port["cpe"]}</span></p>' if port.get('cpe') else ''}
                </div>
            </div>
            """ for port in getattr(host, 'open_ports', []))
            
        def _generate_vulnerability_section(self, host):
            """Generate HTML for vulnerabilities section."""
            if not hasattr(host, 'vulnerabilities') or not host.vulnerabilities:
                return ""
                
            vulnerabilities_html = "".join(self._generate_vulnerability_card(vuln) for vuln in host.vulnerabilities)
            
            return f"""
            <div class="mt-6">
                <h4 class="font-medium text-gray-700 mb-3">Vulnerabilidades:</h4>
                <div class="space-y-3">
                    {vulnerabilities_html}
                </div>
            </div>
            """
            
        def _generate_vulnerability_card(self, vuln):
            """Generate HTML for a single vulnerability."""
            severity = getattr(vuln, 'severity', 'info').lower()
            severity_class = f"vuln-{severity}"
            severity_text = severity.capitalize()
            
            return f"""
            <div class="p-4 rounded-md bg-white border-l-4 {severity_class} shadow-sm">
                <div class="flex justify-between items-start">
                    <div>
                        <h4 class="font-bold">{getattr(vuln, 'name', 'Vulnerabilidad')} <span class="text-sm font-normal text-gray-600">({getattr(vuln, 'cve', 'No CVE')})</span></h4>
                        <p class="text-sm text-gray-700 mt-1">{getattr(vuln, 'description', 'No hay descripción disponible.')}</p>
                        <div class="mt-2 flex flex-wrap gap-2">
                            <span class="px-2 py-1 bg-gray-100 text-gray-800 text-xs rounded-full">
                                <i class="fas fa-bolt mr-1"></i> Severidad: {severity_text}
                            </span>
                            {f'<span class="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full"><i class="fas fa-shield-alt mr-1"></i> CVSS: {getattr(vuln, "cvss_score", "N/A")}</span>' if hasattr(vuln, 'cvss_score') else ''}
                        </div>
                    </div>
                </div>
                
                {self._generate_exploits_section(vuln) if hasattr(vuln, 'exploits') and vuln.exploits else ''}
            </div>
            """
            
        def _generate_exploits_section(self, vuln):
            """Generate HTML for exploits section of a vulnerability."""
            if not hasattr(vuln, 'exploits') or not vuln.exploits:
                return ""
                
            exploits_html = "".join(f"""
            <li class="mt-2">
                <a href="{exploit.get('url', '#')}" target="_blank" class="text-blue-600 hover:underline flex items-center">
                    <i class="fas fa-external-link-alt mr-2"></i>
                    {exploit.get('source', 'Fuente')}: {exploit.get('description', 'Exploit disponible')}
                </a>
            </li>
            """ for exploit in vuln.exploits)
            
            return f"""
            <div class="mt-3 pt-3 border-t border-gray-200">
                <h5 class="text-sm font-medium text-gray-700 mb-2">Exploits disponibles:</h5>
                <ul class="text-sm space-y-1">
                    {exploits_html}
                </ul>
            </div>
            """
            
        def _calculate_risk_level(self):
            """Calculate overall risk level based on vulnerabilities."""
            if not hasattr(self.dashboard, 'results') or not self.dashboard.results:
                return "Bajo"
                
            max_severity = 0  # 0: info, 1: low, 2: medium, 3: high, 4: critical
            severity_map = {
                'info': 0,
                'low': 1,
                'medium': 2,
                'high': 3,
                'critical': 4
            }
            
            for host in self.dashboard.results:
                for vuln in getattr(host, 'vulnerabilities', []):
                    severity = getattr(vuln, 'severity', 'info').lower()
                    max_severity = max(max_severity, severity_map.get(severity, 0))
            
            risk_levels = ['Bajo', 'Moderado', 'Medio', 'Alto', 'Crítico']
            return risk_levels[min(max_severity, len(risk_levels) - 1)]

    def start(self):
        """Start the web server and open the dashboard in the default browser."""
        import http.server
        import socketserver
        import webbrowser
        import threading
        import functools
        
        handler = functools.partial(self.RequestHandler, self)
        
        class Server(socketserver.TCPServer):
            allow_reuse_address = True
        
        try:
            with Server(('0.0.0.0', self.port), handler) as httpd:
                self.server = httpd
                print(f"Servidor web iniciado en http://localhost:{self.port}")
                webbrowser.open(f"http://localhost:{self.port}")
                httpd.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"Error: El puerto {self.port} ya está en uso. Por favor, cierra cualquier otra instancia del servidor.")
                # Verificar que realmente funciona con un escaneo simple
                temp_nm.scan(hosts='127.0.0.1', ports='80', arguments='-T4')
                
                # Si llegamos aquí, la ruta es válida
                self.nm = temp_nm
                self.nm.nmap_path = path
                # Agregar el directorio de Nmap al PATH para futuras llamadas
                nmap_dir = os.path.dirname(path) if os.path.isfile(path) else ''
                if nmap_dir and nmap_dir not in os.environ['PATH']:
                    os.environ['PATH'] = f"{nmap_dir};{os.environ['PATH']}"
                print(f"[+] Usando Nmap en: {path}")
                return
        except Exception as e:
            print(f"[-] Error con {path}: {str(e)}")
        
        if self.nm is None:
            print("""
            [ERROR] No se pudo encontrar Nmap en las ubicaciones estándar.
            Por favor, asegúrate de que Nmap esté instalado y accesible desde la línea de comandos.
            Puedes descargarlo desde: https://nmap.org/download.html
            
            Instrucciones de instalación:
            1. Descarga el instalador de Nmap para Windows
            2. Ejecuta el instalador
            3. Asegúrate de marcar la opción 'Add Nmap to PATH' durante la instalación
            4. Reinicia la terminal después de la instalación
            """)
            exit(1)

    def detect_local_network(self) -> List[str]:
        """Detecta la red local y devuelve una lista de hosts en /24"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ".".join(local_ip.split(".")[:3]) + ".0/24"
            return [str(ip) for ip in ipaddress.IPv4Network(network, strict=False)]
        except Exception as e:
            logging.error(f"Error detectando la red local: {str(e)}")
            return []

    def scan_host(self, host: str, ports: str = None, scan_type: ScanType = ScanType.QUICK, 
                 shodan_key: str = None, suggest_exploits: bool = False) -> ScanResult:
        """Realiza un escaneo avanzado según el tipo especificado"""
        try:
            # Get IP address first
            ip = socket.gethostbyname(host)
            
            if scan_type == ScanType.OSINT:
                return self._osint_scan(host, shodan_key)
            
            args = ""
            if scan_type == ScanType.QUICK:
                args = f"-sV -T4 --top-ports 100"
            elif scan_type == ScanType.STEALTH:
                args = STEALTH_SCAN_ARGS
            elif scan_type == ScanType.OS_DETECTION:
                args = OS_FINGERPRINTING_ARGS
            elif scan_type == ScanType.PASSIVE:
                args = PASSIVE_DETECTION_ARGS
            elif scan_type == ScanType.AGGRESSIVE:
                args = AGGRESSIVE_SCAN_ARGS
            elif scan_type == ScanType.VULNERABILITY:
                args = VULNERABILITY_SCAN_ARGS
            elif scan_type == ScanType.FULL:
                args = "-sS -sV -sC -A -T4 -p-"
            elif scan_type == ScanType.NETWORK:
                args = "-sn"  # Solo descubrimiento de hosts
            
            # Prepare ports string
            ports_to_scan = ports or DEFAULT_PORTS
            
            # Run the scan with ports in the arguments if specified
            if ports:
                args = f"{args} -p {ports}" if args else f"-p {ports}"
                self.nm.scan(hosts=host, arguments=args)
            else:
                self.nm.scan(hosts=host, ports=ports_to_scan, arguments=args)
                
            result = self._parse_scan_results(host, shodan_key, suggest_exploits)
            
            # Si se solicitan sugerencias de exploits, buscarlas para los puertos abiertos
            if suggest_exploits and result and hasattr(result, 'open_ports') and result.open_ports:
                logging.info(f"Buscando exploits para {len(result.open_ports)} puertos abiertos...")
                vulnerabilities = self._suggest_exploits(result.open_ports) or []
                
                # Add debug logging
                logging.info(f"Se encontraron {len(vulnerabilities)} vulnerabilidades potenciales para {host}")
                for i, vuln in enumerate(vulnerabilities, 1):
                    if hasattr(vuln, 'cve'):  # It's a Vulnerability object
                        logging.info(f"{i}. {vuln.cve or 'N/A'} - {vuln.description}")
                    elif isinstance(vuln, dict):  # It's a dictionary
                        logging.info(f"{i}. {vuln.get('cve', 'N/A')} - {vuln.get('description', 'Sin descripción')}")
                
                if hasattr(result, 'vulnerabilities') and isinstance(result.vulnerabilities, list):
                    result.vulnerabilities.extend(vulnerabilities)
                else:
                    result.vulnerabilities = vulnerabilities
                    
            return result
                
        except nmap.PortScannerError as e:
            logging.error(f"Error de Nmap al escanear {host}: {str(e)}")
            # Get IP address even if scan fails
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = "0.0.0.0"  # Fallback IP if hostname resolution fails
            return ScanResult(
                host=host,
                ip=ip,
                open_ports=[],
                is_up=False,
                scan_type=scan_type,
                timestamp=datetime.now().isoformat()
            )
        except socket.gaierror as e:
            logging.error(f"Error de DNS al escanear {host}: {str(e)}")
            return ScanResult(
                host=host,
                ip="0.0.0.0",
                open_ports=[],
                is_up=False,
                scan_type=scan_type,
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            logging.error(f"Error al escanear {host}: {str(e)}", exc_info=True)
            # Get IP address even if scan fails
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = "0.0.0.0"  # Fallback IP if hostname resolution fails
            return ScanResult(
                host=host,
                ip=ip,
                open_ports=[],
                is_up=False,
                scan_type=scan_type,
                timestamp=datetime.now().isoformat()
            )

    def _parse_scan_results(self, host: str, shodan_key: str = None, suggest_exploits: bool = False) -> ScanResult:
        """Procesa los resultados del escaneo y devuelve un objeto ScanResult"""
        if host not in self.nm.all_hosts():
            # Get IP address for the host
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = host  # Use host as IP if resolution fails
            return ScanResult(
                host=host,
                ip=ip,
                open_ports=[],
                timestamp=datetime.now().isoformat()
            )

        host_data = self.nm[host]
        open_ports = []
        
        for proto in self.nm[host].all_protocols():
            for port, info in host_data[proto].items():
                if info['state'] == 'open':
                    open_ports.append({
                        'port': port,
                        'protocol': proto,
                        'service': info.get('name', ''),
                        'version': info.get('version', ''),
                        'product': info.get('product', ''),
                        'cpe': info.get('cpe', '')
                    })

        os_info = host_data.get('osmatch', [{}])[0] if 'osmatch' in host_data else {}
        shodan_data = self._get_shodan_info(host, shodan_key) if shodan_key else None
        
        # Get IP address for the host
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host  # Use host as IP if resolution fails
            
        return ScanResult(
            host=host,
            ip=ip,
            open_ports=open_ports,
            os_info=os_info,
            is_up=bool(open_ports),  # Consider host up if there are open ports
            scan_type=getattr(self, 'current_scan_type', ScanType.QUICK),  # Default to QUICK if not set
            timestamp=datetime.now().isoformat()
        )

    def _osint_scan(self, host: str, shodan_key: str) -> ScanResult:
        """Realiza un escaneo OSINT utilizando fuentes externas"""
        try:
            # Get IP address for the host
            try:
                ip = socket.gethostbyname(host)
            except:
                ip = host  # Use host as IP if resolution fails
                
            # Get Shodan data if API key is provided
            shodan_data = self._get_shodan_info(host, shodan_key) if shodan_key else None
            
            return ScanResult(
                host=host,
                ip=ip,
                open_ports=[],
                is_up=True,  # Assume host is up for OSINT scans
                scan_type=ScanType.OSINT,
                shodan_data=shodan_data,
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            logging.error(f"Error en escaneo OSINT para {host}: {str(e)}")
            return ScanResult(
                host=host,
                ip=ip if 'ip' in locals() else host,
                open_ports=[],
                is_up=False,
                scan_type=ScanType.OSINT,
                timestamp=datetime.now().isoformat()
            )

    def _get_shodan_info(self, host: str, api_key: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de Shodan para la IP objetivo
        
        Args:
            host: Host o IP a consultar
            api_key: Clave de API de Shodan
            
        Returns:
            Diccionario con la información de Shodan o None si hay error
        """
        try:
            response = requests.get(SHODAN_API_URL.format(host, api_key))
            if response.status_code == 200:
                return response.json()
            logging.warning(f"Error en la respuesta de Shodan: {response.status_code}")
        except Exception as e:
            logging.warning(f"No se pudo obtener información de Shodan: {str(e)}")
        return None

    def _suggest_exploits(self, open_ports: List[Dict[str, Any]], batch_size: int = 50) -> List[Dict[str, Any]]:
        """Suggests potential exploits based on open ports and services.
    
        Optimized to handle large numbers of ports efficiently by processing in batches
        and using optimized data structures for lookups.
        
        Args:
            open_ports: List of dictionaries containing port information
            batch_size: Number of ports to process in each batch
            
        Returns:
            List of Vulnerability objects with exploit suggestions
        """
        vulnerabilities = []
        
        # Common vulnerability database - optimized for quick lookups
        VULN_DB = {
        # Port 21 - FTP
        21: {
            'vsftpd': {
                '2.3.4': {
                    'cve': 'CVE-2011-2523',
                    'severity': 'high',
                    'description': 'Backdoor en vsftpd 2.3.4 que permite ejecución remota de comandos',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/exploits/17491',
                            'description': 'vsftpd 2.3.4 Backdoor Command Execution',
                            'type': 'RCE',
                            'platform': 'Linux'
                        },
                        {
                            'source': 'Rapid7',
                            'url': 'https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/',
                            'description': 'Módulo de Metasploit para la vulnerabilidad vsftpd 2.3.4',
                            'type': 'RCE',
                            'platform': 'Linux'
                        }
                    ]
                },
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Múltiples vulnerabilidades en servidores FTP',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ftp',
                            'description': 'Múltiples vulnerabilidades en servidores FTP',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'OWASP',
                            'url': 'https://owasp.org/www-community/attacks/FTPS_and_FTP',
                            'description': 'Ataques comunes contra servidores FTP',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        # Port 22 - SSH
        22: {
            'openssh': {
                '7.2': {
                    'cve': 'CVE-2016-10009',
                    'severity': 'high',
                    'description': 'OpenSSH 7.2p2 Username Enumeration',
                    'exploits': [{
                        'source': 'ExploitDB',
                        'url': 'https://www.exploit-db.com/exploits/40136',
                        'description': 'OpenSSH 7.2p2 - Username Enumeration',
                        'type': 'Information Disclosure',
                        'platform': 'Linux/Unix'
                    }]
                },
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Múltiples vulnerabilidades en servidores SSH',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ssh',
                            'description': 'Múltiples vulnerabilidades en servidores SSH',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'Qualys',
                            'url': 'https://www.qualys.com/2023/10/03/cve-2023-48795/barghami-thread-model.txt',
                            'description': 'Vulnerabilidad Terrapin en SSH (CVE-2023-48795)',
                            'type': 'MitM',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        # Port 80/443 - HTTP/HTTPS
        80: {
            'apache': {
                '2.4.49': {
                    'cve': 'CVE-2021-41773',
                    'severity': 'critical',
                    'description': 'Apache 2.4.49 Path Traversal and RCE',
                    'exploits': [{
                        'source': 'ExploitDB',
                        'url': 'https://www.exploit-db.com/exploits/50406',
                        'description': 'Apache 2.4.49/2.4.50 - Path Traversal & RCE',
                        'type': 'RCE',
                        'platform': 'Cross-Platform'
                    }]
                }
            },
            'http': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Servidor web puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=web+server',
                            'description': 'Múltiples vulnerabilidades en servidores web',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'OWASP',
                            'url': 'https://owasp.org/www-project-top-ten/',
                            'description': 'Top 10 vulnerabilidades web de OWASP',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        443: {
            'apache': {
                '2.4.49': {
                    'cve': 'CVE-2021-41773',
                    'severity': 'critical',
                    'description': 'Apache 2.4.49 Path Traversal and RCE',
                    'exploits': [{
                        'source': 'ExploitDB',
                        'url': 'https://www.exploit-db.com/exploits/50406',
                        'description': 'Apache 2.4.49/2.4.50 - Path Traversal & RCE',
                        'type': 'RCE',
                        'platform': 'Cross-Platform'
                    }]
                }
            },
            'https': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Servicio HTTPS puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ssl+or+tls',
                            'description': 'Múltiples vulnerabilidades en SSL/TLS',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'Qualys SSL Labs',
                            'url': 'https://www.ssllabs.com/ssltest/',
                            'description': 'Herramienta para probar configuraciones SSL/TLS inseguras',
                            'type': 'Scanner',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        # Port 135 - MSRPC
        135: {
            'msrpc': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'high',
                    'description': 'MSRPC ha sido históricamente vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'Rapid7',
                            'url': 'https://www.rapid7.com/db/services/msrpc/',
                            'description': 'Múltiples vulnerabilidades en MSRPC',
                            'type': 'RCE/DoS',
                            'platform': 'Windows'
                        },
                        {
                            'source': 'Microsoft',
                            'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26414',
                            'description': 'Elevación de privilegios en MSRPC',
                            'type': 'EoP',
                            'platform': 'Windows 10/Server 2019'
                        }
                    ]
                }
            }
        },
        # Port 139/445 - SMB/NetBIOS
        139: {
            'netbios-ssn': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'high',
                    'description': 'El servicio NetBIOS Session Service es vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'Rapid7',
                            'url': 'https://www.rapid7.com/db/services/netbios-ssn/',
                            'description': 'Múltiples vulnerabilidades en NetBIOS',
                            'type': 'Multiple',
                            'platform': 'Windows'
                        },
                        {
                            'source': 'Microsoft',
                            'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17096',
                            'description': 'Ejecución remota de código en NetBIOS',
                            'type': 'RCE',
                            'platform': 'Windows 10/Server 2019'
                        }
                    ]
                }
            }
        },
        445: {
            'microsoft-ds': {
                '*': {
                    'cve': 'CVE-2017-0144, CVE-2017-0143, CVE-2020-0796',
                    'severity': 'critical',
                    'description': 'El servicio SMB es vulnerable a varios ataques incluyendo EternalBlue (MS17-010)',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/exploits/41891',
                            'description': 'MS17-010 SMB Remote Windows Command Execution',
                            'type': 'RCE',
                            'platform': 'Windows'
                        },
                        {
                            'source': 'GitHub',
                            'url': 'https://github.com/helviojunior/MS17-010',
                            'description': 'Herramienta de escaneo y explotación para MS17-010',
                            'type': 'Scanner/Exploit',
                            'platform': 'Windows'
                        }
                    ]
                }
            }
        },
        # Port 1433 - MS-SQL
        1433: {
            'ms-sql-s': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'high',
                    'description': 'Microsoft SQL Server puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/exploits/47976',
                            'description': 'SQLi en Microsoft SQL Server',
                            'type': 'SQL Injection',
                            'platform': 'Windows'
                        },
                        {
                            'source': 'Microsoft',
                            'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0618',
                            'description': 'Elevación de privilegios en SQL Server',
                            'type': 'EoP',
                            'platform': 'SQL Server 2019'
                        }
                    ]
                }
            }
        },
        # Port 3306 - MySQL
        3306: {
            'mysql': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'high',
                    'description': 'Servidor MySQL puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=mysql',
                            'description': 'Múltiples vulnerabilidades en MySQL',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'OWASP',
                            'url': 'https://owasp.org/www-community/attacks/SQL_Injection',
                            'description': 'Inyección SQL en MySQL',
                            'type': 'SQL Injection',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        # Port 3389 - RDP
        3389: {
            'ms-wbt-server': {
                '*': {
                    'cve': 'CVE-2019-0708',
                    'severity': 'critical',
                    'description': 'Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)',
                    'exploits': [{
                        'source': 'ExploitDB',
                        'url': 'https://www.exploit-db.com/exploits/46743',
                        'description': 'Microsoft Windows RDP RCE (BlueKeep)',
                        'type': 'RCE',
                        'platform': 'Windows'
                    }]
                }
            }
        },
        # Port 5432 - PostgreSQL
        5432: {
            'postgresql': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'PostgreSQL puede ser vulnerable a varios ataques',
                    'exploits': [{
                        'source': 'ExploitDB',
                        'url': 'https://www.exploit-db.com/search?q=postgresql',
                        'description': 'Múltiples vulnerabilidades en PostgreSQL',
                        'type': 'Multiple',
                        'platform': 'Cross-Platform'
                    }]
                }
            }
        },
        # Port 8080/8443 - HTTP/HTTPS Alternative
        8080: {
            'http-proxy': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'HTTP Proxy service puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=proxy',
                            'description': 'Múltiples vulnerabilidades en HTTP Proxy',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            },
            'http': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Servidor web puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=web+server',
                            'description': 'Múltiples vulnerabilidades en servidores web',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        8443: {
            'https': {
                '*': {
                    'cve': 'Multiple',
                    'severity': 'medium',
                    'description': 'Servicio HTTPS puede ser vulnerable a varios ataques',
                    'exploits': [
                        {
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ssl+or+tls',
                            'description': 'Múltiples vulnerabilidades en SSL/TLS',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        },
                        {
                            'source': 'Qualys SSL Labs',
                            'url': 'https://www.ssllabs.com/ssltest/',
                            'description': 'Herramienta para probar configuraciones SSL/TLS inseguras',
                            'type': 'Scanner',
                            'platform': 'Cross-Platform'
                        }
                    ]
                }
            }
        },
        # Add more ports and services as needed
    }

    def _add_vulnerability(
        self,
        vulnerabilities: List[Vulnerability],
        name: str,
        description: str,
        severity: str,
        cvss_score: Optional[float] = None,
        cve: Optional[str] = None,
        reference: Optional[str] = None,
        solution: Optional[str] = None,
        port: Optional[int] = None,
        service: Optional[str] = None,
        version: Optional[str] = None,
        exploit_url: Optional[str] = None
    ) -> None:
        """Add a vulnerability to the list if it doesn't already exist.
        
        Args:
            vulnerabilities: List to add the vulnerability to
            name: Vulnerability name
            description: Detailed description
            severity: Severity level (critical, high, medium, low, info)
            cvss_score: Optional CVSS score
            cve: Optional CVE ID
            reference: Reference URL
            solution: Recommended solution
            port: Affected port
            service: Affected service
            version: Version of the affected software
            exploit_url: URL to exploit details or PoC
        """
        # Check if vulnerability already exists
        for vuln in vulnerabilities:
            if vuln.name == name and vuln.port == port:
                return
                
        vulnerabilities.append(Vulnerability(
            name=name,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cve=cve,
            reference=reference,
            solution=solution,
            port=port,
            service=service,
            version=version,
            exploit_url=exploit_url
        ))
        logging.info(f"Vulnerabilidad encontrada: {name}")

    def _suggest_exploits(self, open_ports: List[Dict[str, Any]], batch_size: int = 50) -> List[Dict[str, Any]]:
        """Suggests potential exploits based on open ports and services.
    
        Optimized to handle large numbers of ports efficiently by processing in batches
        and using optimized data structures for lookups.
        
        Args:
            open_ports: List of dictionaries containing port information
            batch_size: Number of ports to process in each batch
            
        Returns:
            List of Vulnerability objects with exploit suggestions
        """
        vulnerabilities = []
        
        # Vulnerability database
        VULN_DB = {
            # Port 135 - MSRPC
            135: {
                'msrpc': {
                    '*': {
                        'cve': 'Multiple',
                        'severity': 'high',
                        'description': 'MSRPC has been historically vulnerable to various attacks',
                        'exploits': [{
                            'source': 'Rapid7',
                            'url': 'https://www.rapid7.com/db/services/msrpc/',
                            'description': 'Multiple MSRPC vulnerabilities',
                            'type': 'RCE/DoS',
                            'platform': 'Windows'
                        }]
                    }
                }
            },
            # Port 139/445 - SMB
            139: {
                'netbios-ssn': {
                    '*': {
                        'cve': 'Multiple',
                        'severity': 'high',
                        'description': 'NetBIOS Session Service may be vulnerable to various attacks',
                        'exploits': [{
                            'source': 'Rapid7',
                            'url': 'https://www.rapid7.com/db/services/netbios-ssn/',
                            'description': 'Multiple NetBIOS vulnerabilities',
                            'type': 'Multiple',
                            'platform': 'Windows'
                        }]
                    }
                }
            },
            445: {
                'microsoft-ds': {
                    '*': {
                        'cve': 'CVE-2017-0144, CVE-2017-0143, CVE-2020-0796',
                        'severity': 'critical',
                        'description': 'SMB service is vulnerable to various attacks including EternalBlue (MS17-010)',
                        'exploits': [
                            {
                                'source': 'ExploitDB',
                                'url': 'https://www.exploit-db.com/exploits/41891',
                                'description': 'MS17-010 SMB Remote Windows Command Execution',
                                'type': 'RCE',
                                'platform': 'Windows'
                            }
                        ]
                    }
                }
            },
            # Port 80/443 - HTTP/HTTPS
            80: {
                'http': {
                    '*': {
                        'cve': 'Multiple',
                        'severity': 'medium',
                        'description': 'Web server may be vulnerable to various attacks',
                        'exploits': [{
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=web+server',
                            'description': 'Multiple web server vulnerabilities',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }]
                    }
                }
            },
            443: {
                'https': {
                    '*': {
                        'cve': 'Multiple',
                        'severity': 'medium',
                        'description': 'HTTPS service may be vulnerable to various attacks',
                        'exploits': [{
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ssl+or+tls',
                            'description': 'Multiple SSL/TLS vulnerabilities',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }]
                    }
                }
            },
            # Port 22 - SSH
            22: {
                'ssh': {
                    '*': {
                        'cve': 'Multiple',
                        'severity': 'high',
                        'description': 'SSH service may be vulnerable to various attacks',
                        'exploits': [{
                            'source': 'ExploitDB',
                            'url': 'https://www.exploit-db.com/search?q=ssh',
                            'description': 'Multiple SSH vulnerabilities',
                            'type': 'Multiple',
                            'platform': 'Cross-Platform'
                        }]
                    }
                }
            }
        }
        
        # Process ports in batches
        for port_info in open_ports:
            port = port_info.get('port')
            service = str(port_info.get('service', '')).lower()
            version = str(port_info.get('version', '')).lower()
            
            logging.info(f"Procesando puerto {port} - Servicio: {service} - Versión: {version}")
            
            if port in VULN_DB:
                port_vulns = VULN_DB[port]
                
                # Try exact match first
                matched = False
                for db_service, versions in port_vulns.items():
                    # Check if the service name is in the detected service (case-insensitive)
                    if db_service.lower() in service.lower() or service.lower() in db_service.lower():
                        logging.info(f"Coincidencia de servicio encontrada: {db_service}")
                        
                        # Try exact version match first
                        if version in versions:
                            vuln_details = versions[version]
                            self._add_vulnerability(vulnerabilities, 
                                                    f"Exploit Sugerido: {vuln_details.get('exploits', [{}])[0].get('description', 'Vulnerabilidad conocida')}", 
                                                    f"Posible exploit para {service} {version} en puerto {port}. {vuln_details.get('description', '')}", 
                                                    vuln_details.get('severity', 'medium'), 
                                                    None, 
                                                    vuln_details.get('cve', 'N/A'), 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''), 
                                                    "Investigar y aplicar parches de seguridad o configuraciones recomendadas.", 
                                                    port, 
                                                    service, 
                                                    version, 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''))
                            matched = True
                            continue
                        
                        # Try wildcard version
                        if '*' in versions:
                            vuln_details = versions['*']
                            self._add_vulnerability(vulnerabilities, 
                                                    f"Exploit Sugerido: {vuln_details.get('exploits', [{}])[0].get('description', 'Vulnerabilidad conocida')}", 
                                                    f"Posible exploit para {service} {version} en puerto {port}. {vuln_details.get('description', '')}", 
                                                    vuln_details.get('severity', 'medium'), 
                                                    None, 
                                                    vuln_details.get('cve', 'N/A'), 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''), 
                                                    "Investigar y aplicar parches de seguridad o configuraciones recomendadas.", 
                                                    port, 
                                                    service, 
                                                    version, 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''))
                            matched = True
                
                # If no match yet, try partial service name matching
                if not matched:
                    for service_part in service.split():
                        if service_part in versions:
                            vuln_details = versions[service_part]
                            self._add_vulnerability(vulnerabilities, 
                                                    f"Exploit Sugerido: {vuln_details.get('exploits', [{}])[0].get('description', 'Vulnerabilidad conocida')}", 
                                                    f"Posible exploit para {service} {version} en puerto {port}. {vuln_details.get('description', '')}", 
                                                    vuln_details.get('severity', 'medium'), 
                                                    None, 
                                                    vuln_details.get('cve', 'N/A'), 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''), 
                                                    "Investigar y aplicar parches de seguridad o configuraciones recomendadas.", 
                                                    port, 
                                                    service, 
                                                    version, 
                                                    vuln_details.get('exploits', [{}])[0].get('url', ''))
                            matched = True
                            break
                
                # If still no match, check for any service on this port
                if not matched and '*' in port_vulns:
                    for versions in port_vulns.values():
                        if '*' in versions:
                            self._add_vulnerability(
                                vulnerabilities, 
                                f"Exploit Sugerido: {versions['*'].get('exploits', [{}])[0].get('description', 'Vulnerabilidad conocida')}", 
                                f"Posible exploit para {service} {version} en puerto {port}. {versions['*'].get('description', '')}", 
                                versions['*'].get('severity', 'medium'), 
                                None, 
                                versions['*'].get('cve', 'N/A'), 
                                versions['*'].get('exploits', [{}])[0].get('url', ''), 
                                "Investigar y aplicar parches de seguridad o configuraciones recomendadas.", 
                                port, 
                                service, 
                                version,
                                versions['*'].get('exploits', [{}])[0].get('url', '')
                            )
        
        return vulnerabilities
    
    def start(self):
        """Start the web server and open the dashboard in the default browser."""
        class RequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.results = kwargs.pop('results', [])
                super().__init__(*args, directory=str(Path(__file__).parent), **kwargs)
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(HTTPStatus.OK)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self._generate_html().encode('utf-8'))
                else:
                    super().do_GET()
            
            def _generate_html(self):
                """Generate the HTML dashboard with scan results."""
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Network Scanner Results</title>
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                </head>
                <body class="bg-gray-100 p-8">
                    <div class="max-w-6xl mx-auto">
                        <h1 class="text-3xl font-bold mb-8">Network Scan Results</h1>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            {self._generate_host_cards()}
                        </div>
                    </div>
                </body>
                </html>
                """
                return html
            
            def _generate_host_cards(self):
                """Generate HTML cards for each host."""
                cards = []
                for result in self.results:
                    card = f"""
                    <div class="bg-white rounded-lg shadow-md p-6">
                        <h2 class="text-xl font-semibold mb-4">{getattr(result, 'host', 'Unknown Host')} ({getattr(result, 'ip', 'N/A')})</h2>
                        <div class="space-y-4">
                            {self._generate_ports_section(result)}
                            {self._generate_vulnerabilities_section(result)}
                        </div>
                    </div>
                    """
                    cards.append(card)
                return "\n".join(cards)
            
            def _generate_ports_section(self, result):
                """Generate the ports section for a host."""
                if not hasattr(result, 'open_ports') or not result.open_ports:
                    return '<p class="text-gray-600">No open ports found</p>'
                
                ports_html = []
                for port in result.open_ports:
                    if isinstance(port, dict):
                        port_num = port.get('port', '')
                        protocol = port.get('protocol', 'tcp')
                        service = port.get('service', 'Unknown')
                        version = port.get('version', '')
                        ports_html.append(
                            f'<div class="flex justify-between items-center p-2 bg-gray-50 rounded">'
                            f'<span class="font-medium">Port {port_num}/{protocol}</span>'
                            f'<span class="text-sm text-gray-600">{service} {version}</span>'
                            f'</div>'
                        )
                return "".join(ports_html)
            
            def _generate_vulnerabilities_section(self, result):
                """Generate the vulnerabilities section for a host."""
                if not hasattr(result, 'vulnerabilities') or not result.vulnerabilities:
                    return ""
                
                vulns_html = []
                for vuln in result.vulnerabilities:
                    if isinstance(vuln, dict):
                        port_info = vuln.get('port', '?')
                        service_info = vuln.get('service', '') + ' ' + vuln.get('version', '')
                        severity = vuln.get('vulnerability', {}).get('severity', 'info').lower()
                        name = vuln.get('vulnerability', {}).get('cve', 'Vulnerability')
                        description = vuln.get('vulnerability', {}).get('description', '')
                        
                        # Determine severity color
                        if 'critical' in severity:
                            border_color = 'border-red-500'
                            text_color = 'text-red-600'
                        elif 'high' in severity:
                            border_color = 'border-orange-500'
                            text_color = 'text-orange-600'
                        elif 'medium' in severity:
                            border_color = 'border-yellow-500'
                            text_color = 'text-yellow-600'
                        elif 'low' in severity:
                            border_color = 'border-blue-500'
                            text_color = 'text-blue-600'
                        else:
                            border_color = 'border-gray-500'
                            text_color = 'text-gray-600'
                        
                        vulns_html.append(
                            f'<div class="p-3 rounded border-l-4 {border_color} bg-gray-50 mt-2">'
                            f'<div class="font-medium">{name}</div>'
                            f'<div class="text-sm text-gray-600">{description}</div>'
                            f'<div class="text-xs mt-1"><span class="font-medium">Severity:</span> <span class="{text_color}">{severity.upper()}</span></div>'
                            f'<div class="text-xs mt-1"><span class="font-medium">Port:</span> {port_info}</div>'
                            f'<div class="text-xs mt-1"><span class="font-medium">Service:</span> {service_info}</div>'
                            f'</div>'
                        )
                
                if not vulns_html:
                    return ""
                    
                return f"""
                <div class="mt-4">
                    <h3 class="text-lg font-medium mb-2">Vulnerabilities</h3>
                    <div class="space-y-2">
                        {"".join(vulns_html)}
                    </div>
                </div>
                """
        
        # Start the server in a separate thread
        def run_server():
            class Server(socketserver.TCPServer):
                allow_reuse_address = True
                
                def __init__(self, *args, **kwargs):
                    self.results = kwargs.pop('results', [])
                    super().__init__(*args, **kwargs)
                
                def finish_request(self, request, client_address):
                    self.RequestHandlerClass(
                        request, 
                        client_address, 
                        self,
                        results=self.results
                    )
            
            with Server(("", self.port), RequestHandler) as httpd:
                httpd.results = self.results
                self.server = httpd
                webbrowser.open(f"http://localhost:{self.port}")
                httpd.serve_forever()
        
        # Start the server in a daemon thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        return self

class WebDashboard:
    """Web dashboard for displaying scan results interactively."""
    
    def __init__(self, results, port=8000):
        """Initialize the web dashboard with scan results.
        
        Args:
            results: List of ScanResult objects
            port: Port to run the web server on (default: 8000)
        """
        self.results = results if isinstance(results, list) else [results]
        self.port = port
        self.server = None
        
    def generate_html(self):
        """Generate the HTML content for the dashboard."""
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Network Scanner Results</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
            <style>
                .host-card { transition: all 0.3s ease; }
                .host-card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }
                .vuln-critical { border-left: 4px solid #dc2626; }
                .vuln-high { border-left: 4px solid #ea580c; }
                .vuln-medium { border-left: 4px solid #d97706; }
                .vuln-low { border-left: 4px solid #65a30d; }
                .vuln-info { border-left: 4px solid #0891b2; }
            </style>
        </head>
        <body class="bg-gray-100">
            <div class="container mx-auto px-4 py-8">
                <h1 class="text-3xl font-bold text-center mb-8">Network Scan Results</h1>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        """
        
        for result in self.results:
            html += self._generate_host_card(result)
            
        html += """
                </div>
            </div>
            <script>
                // Toggle host details
                document.querySelectorAll('.toggle-details').forEach(button => {
                    button.addEventListener('click', function() {
                        const details = this.nextElementSibling;
                        details.classList.toggle('hidden');
                        const icon = this.querySelector('i');
                        icon.classList.toggle('fa-chevron-down');
                        icon.classList.toggle('fa-chevron-up');
                    });
                });
            </script>
        </body>
        </html>
        """
        return html
    
    def _generate_host_card(self, result):
        """Generate HTML for a single host card."""
        hostname = result.hostname or result.ip
        open_ports = len(result.open_ports) if result.open_ports else 0
        vuln_count = len(result.vulnerabilities) if hasattr(result, 'vulnerabilities') else 0
        
        card = f"""
        <div class="host-card bg-white rounded-lg shadow-md overflow-hidden">
            <div class="p-6">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-xl font-semibold">{hostname}</h2>
                    <span class="px-2 py-1 bg-blue-100 text-blue-800 text-sm rounded-full">
                        {result.ip}
                    </span>
                </div>
                
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-500">Status:</span>
                        <span class="font-medium">
                            <i class="fas fa-circle text-green-500 mr-1"></i> Online
                        </span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-500">Open Ports:</span>
                        <span class="font-medium">{open_ports}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-500">Vulnerabilities:</span>
                        <span class="font-medium">{vuln_count}</span>
                    </div>
                </div>
                
                <button class="toggle-details mt-4 w-full py-2 bg-blue-50 text-blue-600 rounded-md hover:bg-blue-100 
                           transition-colors flex items-center justify-center space-x-2">
                    <span>Show Details</span>
                    <i class="fas fa-chevron-down text-xs"></i>
                </button>
                
                <div class="host-details hidden mt-4 pt-4 border-t border-gray-100">
                    <h3 class="font-medium mb-2">Open Ports:</h3>
                    <div class="space-y-2">
        """
        
        for port in result.open_ports[:5]:  # Show up to 5 ports
            service = port.get('service', 'unknown')
            version = port.get('version', '')
            card += f"""
                    <div class="flex justify-between text-sm">
                        <span class="text-gray-600">Port {port['port']}/{port.get('protocol', 'tcp')}</span>
                        <span class="text-gray-800 font-medium">{service} {version}</span>
                    </div>
            """
            
        if len(result.open_ports) > 5:
            card += f"""
                    <div class="text-sm text-gray-500 italic">
                        + {len(result.open_ports) - 5} more ports...
                    </div>
            """
            
        card += """
                    </div>
                </div>
            </div>
        </div>
        """
        return card
    
    def start(self):
        """Start the web server."""
        class RequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                # Remove the directory argument if it exists
                kwargs.pop('directory', None)
                super().__init__(*args, **kwargs)
                
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self.server.dashboard.generate_html().encode('utf-8'))
                else:
                    super().do_GET()
        
        class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True
        
        # Create server instance
        server = ThreadedHTTPServer(('', self.port), RequestHandler)
        # Set the dashboard instance on the server
        server.dashboard = self
        
        try:
            print(f"Starting web server at http://localhost:{self.port}")
            webbrowser.open(f"http://localhost:{self.port}")
            server.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"Error: Port {self.port} is already in use. Please close any other server using this port.")
            else:
                print(f"Error starting web server: {e}")
        except KeyboardInterrupt:
            print("\nStopping web server...")
            server.shutdown()

@click.command()
@click.option('--host', help='IP o hostname a escanear')
@click.option('--hosts-file', type=click.Path(exists=True), help='Archivo con lista de hosts a escanear')
@click.option('--ports', default=DEFAULT_PORTS, help='Puertos a escanear (por defecto: puertos comunes)')
@click.option('--scan-type', type=click.Choice([t.value for t in ScanType]), 
              default=ScanType.QUICK.value, help='Tipo de escaneo a realizar')
@click.option('--shodan-key', help='Clave de API de Shodan para búsquedas OSINT')
@click.option('--output', type=click.Choice(['text', 'json', 'xml', 'web']), default='text',
              help='Formato de salida')
@click.option('--output-file', help='Archivo de salida (opcional)')
@click.option('--suggest-exploits', is_flag=True, help='Mostrar sugerencias de exploits para vulnerabilidades encontradas')
def cli(host, hosts_file, ports, scan_type, shodan_key, output, output_file, suggest_exploits):
    """Escáner de red avanzado con múltiples modos de operación"""
    scanner = AdvancedNmapScanner()
    results = []
    
    # Determinar lista de hosts a escanear
    hosts = []
    if host:
        hosts.append(host)
    elif hosts_file:
        with open(hosts_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        # Escaneo de red local por defecto
        click.echo("Escaneando red local...")
        hosts = scanner.detect_local_network()
        if not hosts:
            click.echo("No se pudo detectar la red local. Especifique un host con --host o un archivo con --hosts-file")
            return
    
    # Realizar escaneos
    for target in hosts:
        click.echo(f"Escaneando {target}...")
        result = scanner.scan_host(
            host=target,
            ports=ports,
            scan_type=ScanType(scan_type),
            shodan_key=shodan_key,
            suggest_exploits=suggest_exploits
        )
        results.append(result)
    
    # Mostrar resultados
    if output == 'json':
        output_data = [r.__dict__ for r in results]
        output_str = json.dumps(output_data, indent=2)
        
        # Si se solicitaron sugerencias de exploits, asegurarse de que estén incluidas
        if suggest_exploits:
            for result in output_data:
                if 'vulnerabilities' not in result or not result['vulnerabilities']:
                    result['vulnerabilities'] = []
    elif output == 'xml':
        output_str = "<scan_results>"
        for result in results:
            output_str += f"\n  <host ip='{result.host}'>"
            for port in result.open_ports:
                output_str += f"\n    <port number='{port['port']}' protocol='{port['protocol']}'>"
                output_str += f"\n      <service>{port.get('service', '')}</service>"
                output_str += f"\n      <version>{port.get('version', '')}</version>"
                output_str += "\n    </port>"
            
            if result.os_info:
                output_str += f"\n    <os name='{result.os_info.get('name', '')}' accuracy='{result.os_info.get('accuracy', '0')}'/>"
            
            output_str += "\n  </host>"
        output_str += "\n</scan_results>"
    elif output == 'web':
        dashboard = WebDashboard(results)
        dashboard.start()
        click.echo("Presiona Ctrl+C para detener el servidor web...")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            click.echo("\nDeteniendo el servidor web...")
            return
    else:  # text
        output_str = "Resultados del escaneo:\n"
        for result in results:
            output_str += f"\nHost: {result.host}"
            if result.open_ports:
                output_str += "\nPuertos abiertos:"
                for port in result.open_ports:
                    output_str += f"\n  {port['port']}/{port['protocol']}: {port.get('service', '')} {port.get('version', '')}"
            else:
                output_str += "\nNo se encontraron puertos abiertos."
            
            if result.os_info:
                output_str += f"\nSistema operativo probable: {result.os_info.get('name', 'Desconocido')} ({result.os_info.get('accuracy', '0')}% de precisión)"
            
            # Mostrar vulnerabilidades si existen o si se solicitó la búsqueda de exploits
            if suggest_exploits and hasattr(result, 'vulnerabilities') and result.vulnerabilities:
                output_str += "\n\n[!] ANALIZANDO VULNERABILIDADES..."
                output_str += "\n\n[!] VULNERABILIDADES DETECTADAS:"
                for vuln in result.vulnerabilities:
                    if hasattr(vuln, 'port'):  # It's a Vulnerability object
                        port_info = vuln.port or '?'
                        service_info = f"{vuln.service or ''} {vuln.version or ''}".strip()
                        severity = vuln.severity.lower() if hasattr(vuln, 'severity') else 'info'
                        name = vuln.cve or 'Vulnerability'
                        description = vuln.description or ''
                        reference = vuln.reference or ''
                        
                        output_str += f"\n\n[!] {port_info} - {service_info}"
                        output_str += f"\n   • CVE: {name}"
                        output_str += f"\n   • Gravedad: {severity.upper() if severity else 'MEDIA'}"
                        output_str += f"\n   • Descripción: {description}"
                        
                        # Add reference if available
                        if reference:
                            output_str += f"\n   • Referencia: {reference}"
                            
                    elif isinstance(vuln, dict):  # For backward compatibility
                        port_info = vuln.get('port', '?')
                        service_info = vuln.get('service', '') + ' ' + vuln.get('version', '')
                        severity = vuln.get('vulnerability', {}).get('severity', 'info').lower()
                        name = vuln.get('vulnerability', {}).get('cve', 'Vulnerability')
                        description = vuln.get('vulnerability', {}).get('description', '')
                        
                        output_str += f"\n\n[!] {port_info} - {service_info}"
                        output_str += f"\n   • CVE: {name}"
                        output_str += f"\n   • Gravedad: {severity.upper() if isinstance(severity, str) else 'MEDIA'}"
                        output_str += f"\n   • Descripción: {description}"
                        
                        if 'exploits' in vuln.get('vulnerability', {}) and vuln['vulnerability']['exploits']:
                            output_str += "\n   • Exploits disponibles:"
                            for exploit in vuln['vulnerability']['exploits']:
                                if isinstance(exploit, dict):
                                    output_str += f"\n     - {exploit.get('source', 'Fuente desconocida')}: {exploit.get('url', 'URL no disponible')}"
                                    output_str += f"\n       {exploit.get('description', 'Sin descripción')}"
                    else:
                        output_str += "\n   • Información de vulnerabilidad no disponible en formato esperado"
            
            if result.shodan_data:
                output_str += f"\nDatos de Shodan: {json.dumps(result.shodan_data, indent=2)}"
            
            output_str += "\n" + "="*50 + "\n"
    
    # Mostrar y/o guardar resultados
    if output != 'web':  # No guardar archivo en modo web
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_str)
            click.echo(f"Resultados guardados en {output_file}")
        else:
            click.echo(output_str)

def show_banner():
    banner = """
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
    ████╗  ██║██╔════╝██║ ██╔╝██║   ██║██╔════╝
    ██╔██╗ ██║█████╗  █████╔╝ ██║   ██║█████╗  
    ██║╚██╗██║██╔══╝  ██╔═██╗ ██║   ██║██╔══╝  
    ██║ ╚████║███████╗██║  ██╗╚██████╔╝███████╗
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██║  ██║█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    """
    print(banner)

if __name__ == "__main__":
    show_banner()
    cli()