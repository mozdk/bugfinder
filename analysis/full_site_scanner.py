"""
Full Site Scanner - Comprehensive website security scanning with subdomain enumeration.
"""

import re
import json
import time
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "app", "dev", "test", "blog", "shop", "support",
]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/phpinfo.php", "/backup",
    "/phpmyadmin", "/adminer",
]

API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
    "/swagger", "/openapi", "/swagger.json", "/openapi.json",
]

TECHNOLOGY_FINGERPRINTS = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Joomla": [r"joomla", r"/administrator/"],
    "Drupal": [r"drupal", r"sites/default"],
    "Laravel": [r"laravel"],
    "PHP": [r"php", r"PHPSESSID"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "Cloudflare": [r"cloudflare"],
}

@dataclass
class Subdomain:
    name: str
    full_domain: str
    ip_addresses: List[str] = field(default_factory=list)
    is_alive: bool = False
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "full_domain": self.full_domain,
            "ip_addresses": self.ip_addresses,
            "is_alive": self.is_alive,
            "technologies": self.technologies,
        }

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    is_api: bool = False
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "is_api": self.is_api,
            "parameters": self.parameters,
            "forms": self.forms,
        }

@dataclass
class Vulnerability:
    name: str
    category: str
    severity: str
    confidence: float
    description: str
    url: str = ""
    endpoint: str = ""
    payload: str = ""
    proof_of_concept: str = ""
    exploitation_steps: str = ""
    impact: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "url": self.url,
            "endpoint": self.endpoint,
            "payload": self.payload,
            "proof_of_concept": self.proof_of_concept,
            "exploitation_steps": self.exploitation_steps,
            "impact": self.impact,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "references": self.references,
            "recommendation": self.recommendation,
        }

@dataclass
class FullScanResult:
    target_domain: str
    scan_start: datetime
    scan_end: datetime
    subdomains: List[Subdomain] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    info: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "target_domain": self.target_domain,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "subdomains": [s.to_dict() for s in self.subdomains],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "technologies": self.technologies,
            "info": self.info,
        }

class FullSiteScanner:
    def __init__(self, max_threads=3, timeout=5, user_agent="Mozilla/5.0"):
        self.max_threads = max_threads
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def _normalize_domain(self, domain: str) -> str:
        domain = domain.strip()
        if domain.startswith("http://") or domain.startswith("https://"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def _resolve_domain(self, domain: str) -> List[str]:
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            return [ip for ip in ip_addresses if self._is_valid_ip(ip)]
        except:
            return []

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    def _check_accessible(self, url: str) -> Tuple[bool, int, Dict]:
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return True, response.status_code, response.headers
        except Exception as e:
            return False, 0, {}

    def _enumerate_subdomains(self, domain: str) -> List[Subdomain]:
        subdomains = []
        for sub in COMMON_SUBDOMAINS:
            full_domain = f"{sub}.{domain}"
            ip_addresses = self._resolve_domain(full_domain)
            subdomain = Subdomain(
                name=sub,
                full_domain=full_domain,
                ip_addresses=ip_addresses,
                is_alive=len(ip_addresses) > 0
            )
            subdomains.append(subdomain)
            if subdomain.is_alive:
                print(f"[FOUND] {full_domain} -> {ip_addresses}")
        return subdomains

    def _scan_subdomain(self, subdomain: Subdomain) -> Subdomain:
        base_url = f"https://{subdomain.full_domain}"
        try:
            accessible, status, headers = self._check_accessible(base_url)
            if accessible:
                subdomain.is_alive = True
                tech = self._detect_tech(base_url, headers)
                subdomain.technologies.extend(tech)
        except Exception as e:
            print(f"[ERROR] Scanning {subdomain.full_domain}: {e}")
        return subdomain

    def _crawl_subdomain(self, base_url: str) -> List[Endpoint]:
        endpoints = []
        try:
            response = self.session.get(base_url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a', href=True):
                url = urljoin(base_url, link['href'])
                if self._is_valid_url(url, base_url):
                    endpoints.append(Endpoint(url=url, status_code=response.status_code))
            for form in soup.find_all('form', action=True):
                endpoints.append(Endpoint(url=urljoin(base_url, form['action']), method=form.get('method', 'GET').upper()))
        except Exception as e:
            print(f"[ERROR] Crawling {base_url}: {e}")
        return endpoints

    def _is_valid_url(self, url: str, base_url: str) -> bool:
        parsed = urlparse(url)
        base_parsed = urlparse(base_url)
        return parsed.netloc == base_parsed.netloc or not parsed.netloc

    def _detect_tech(self, url: str, headers: Dict = None) -> List[str]:
        tech = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text
            for tech_name, patterns in TECHNOLOGY_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        tech.append(tech_name)
                        break
            if headers:
                server = headers.get('Server', '')
                if server:
                    tech.append(server.split('/')[0])
        except:
            pass
        return list(set(tech))

    def _test_vulnerabilities(self, endpoints: List[Endpoint]) -> List[Vulnerability]:
        vulnerabilities = []
        for endpoint in endpoints:
            vulns = self._test_endpoint(endpoint)
            vulnerabilities.extend(vulns)
        return vulnerabilities

    def _test_endpoint(self, endpoint: Endpoint) -> List[Vulnerability]:
        vulns = []
        try:
            vulns.extend(self._test_sqli(endpoint))
            vulns.extend(self._test_xss(endpoint))
            vulns.extend(self._test_headers(endpoint))
            vulns.extend(self._test_misconfigs(endpoint))
        except Exception as e:
            print(f"[ERROR] Testing {endpoint.url}: {e}")
        return vulns

    def _test_sqli(self, endpoint: Endpoint) -> List[Vulnerability]:
        vulns = []
        payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--"]
        for payload in payloads:
            test_url = f"{endpoint.url}?test={payload}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if self._has_sql_error(response.text):
                    vulns.append(Vulnerability(
                        name="SQL Injection",
                        category="sqli",
                        severity="HIGH",
                        confidence=0.8,
                        description=f"SQL Injection vulnerability detected at {endpoint.url}",
                        url=test_url,
                        endpoint=endpoint.url,
                        payload=payload,
                        exploitation_steps=f"Send request with payload: {payload}",
                        impact="Database compromise, data exfiltration",
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-89",
                        recommendation="Use prepared statements, parameterized queries, validate and sanitize all inputs",
                        proof_of_concept=f"GET {test_url}"
                    ))
            except:
                pass
        return vulns

    def _has_sql_error(self, text: str) -> bool:
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"Unclosed quotation mark",
            r"syntax error.*SQL", r"ODBC Driver.*for SQL", r"ORA-\d{5}",
            r"Microsoft OLE DB", r"syntax error.*PostgreSQL", r"Warning.*pg_"
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _test_xss(self, endpoint: Endpoint) -> List[Vulnerability]:
        vulns = []
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for payload in payloads:
            test_url = f"{endpoint.url}?test={payload}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    vulns.append(Vulnerability(
                        name="Cross-Site Scripting (XSS)",
                        category="xss",
                        severity="HIGH",
                        confidence=0.9,
                        description=f"XSS vulnerability detected at {endpoint.url}",
                        url=test_url,
                        endpoint=endpoint.url,
                        payload=payload,
                        exploitation_steps=f"Send request with payload: {payload}",
                        impact="Session hijacking, defacement, phishing",
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                        cwe_id="CWE-79",
                        recommendation="Sanitize user input, use Content-Security-Policy headers, encode output",
                        proof_of_concept=f"GET {test_url}"
                    ))
            except:
                pass
        return vulns

    def _test_headers(self, endpoint: Endpoint) -> List[Vulnerability]:
        vulns = []
        try:
            response = self.session.get(endpoint.url, timeout=self.timeout)
            headers = response.headers
            missing = []
            if 'Content-Security-Policy' not in headers:
                missing.append('Content-Security-Policy')
            if 'X-Frame-Options' not in headers:
                missing.append('X-Frame-Options')
            if 'X-Content-Type-Options' not in headers:
                missing.append('X-Content-Type-Options')
            if 'Strict-Transport-Security' not in headers:
                missing.append('Strict-Transport-Security')
            if missing:
                vulns.append(Vulnerability(
                    name="Missing Security Headers",
                    category="misconfiguration",
                    severity="HIGH",
                    confidence=1.0,
                    description=f"Missing security headers: {', '.join(missing)}",
                    url=endpoint.url,
                    endpoint=endpoint.url,
                    impact="Increased attack surface, XSS, clickjacking, MIME sniffing vulnerabilities",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    cwe_id="CWE-693",
                    recommendation=f"Add missing headers: {', '.join(missing)}",
                    exploitation_steps="Attacker can exploit XSS, clickjacking, or MIME sniffing vulnerabilities"
                ))
        except:
            pass
        return vulns

    def _test_misconfigs(self, endpoint: Endpoint) -> List[Vulnerability]:
        vulns = []
        for path in SENSITIVE_PATHS:
            test_url = f"{endpoint.url.rstrip('/')}{path}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    vulns.append(Vulnerability(
                        name="Sensitive File Exposure",
                        category="misconfiguration",
                        severity="HIGH",
                        confidence=0.9,
                        description=f"Sensitive file accessible: {path}",
                        url=test_url,
                        endpoint=endpoint.url,
                        impact="Source code exposure, configuration leaks, credential disclosure",
                        cvss_score=8.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-530",
                        recommendation=f"Remove or restrict access to {path}",
                        exploitation_steps=f"Access {test_url} to view sensitive information"
                    ))
            except:
                pass
        return vulns

    def scan(self, domain: str, deep: bool = True) -> FullScanResult:
        start_time = datetime.now()
        domain = self._normalize_domain(domain)
        result = FullScanResult(target_domain=domain, scan_start=start_time, scan_end=start_time)

        print(f"[INFO] Starting full scan of {domain}")

        print("[INFO] Enumerating subdomains...")
        result.subdomains = self._enumerate_subdomains(domain)
        print(f"[INFO] Found {len(result.subdomains)} subdomains")

        print("[INFO] Scanning alive subdomains...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._scan_subdomain, sub) for sub in result.subdomains if sub.is_alive]
            for future in as_completed(futures):
                result.subdomains[result.subdomains.index(future.result())] = future.result()

        print("[INFO] Discovering endpoints...")
        for subdomain in result.subdomains:
            if subdomain.is_alive:
                base_url = f"https://{subdomain.full_domain}"
                endpoints = self._crawl_subdomain(base_url)
                result.endpoints.extend(endpoints)

        print("[INFO] Detecting technologies...")
        for subdomain in result.subdomains:
            if subdomain.is_alive:
                tech = self._detect_tech(f"https://{subdomain.full_domain}")
                result.technologies.extend(tech)
        result.technologies = list(set(result.technologies))

        print("[INFO] Running vulnerability tests...")
        result.vulnerabilities = self._test_vulnerabilities(result.endpoints)

        result.scan_end = datetime.now()
        print(f"[INFO] Scan completed. Found {len(result.vulnerabilities)} vulnerabilities.")
        return result

    def generate_report(self, scan_result: FullScanResult, output_format: str = "text") -> str:
        if output_format == "json":
            return json.dumps(scan_result.to_dict(), indent=2)

        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append("")
        report.append("SCAN INFORMATION")
        report.append("-" * 80)
        report.append(f"Target Domain: {scan_result.target_domain}")
        report.append(f"Scan Start: {scan_result.scan_start}")
        report.append(f"Scan End: {scan_result.scan_end}")
        report.append(f"Duration: {scan_result.scan_end - scan_result.scan_start}")
        report.append("")
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Vulnerabilities: {len(scan_result.vulnerabilities)}")
        high_count = len([v for v in scan_result.vulnerabilities if v.severity == "HIGH"])
        medium_count = len([v for v in scan_result.vulnerabilities if v.severity == "MEDIUM"])
        low_count = len([v for v in scan_result.vulnerabilities if v.severity == "LOW"])
        risk_level = "CRITICAL" if high_count > 0 else "HIGH" if medium_count > 0 else "LOW"
        report.append(f"Risk Level: {risk_level} ({high_count * 30 + medium_count * 20 + low_count * 10:.1f}%)")
        report.append(f"Subdomains Found: {len(scan_result.subdomains)}")
        alive_count = len([s for s in scan_result.subdomains if s.is_alive])
        report.append(f"Alive Subdomains: {alive_count}")
        report.append(f"Endpoints Discovered: {len(scan_result.endpoints)}")
        report.append(f"Technologies: {', '.join(scan_result.technologies) if scan_result.technologies else 'None'}")
        report.append("")
        report.append("TECHNOLOGIES DETECTED")
        report.append("-" * 80)
        if scan_result.technologies:
            for tech in scan_result.technologies:
                report.append(f"• {tech}")
        else:
            report.append("No technologies detected")
        report.append("")
        report.append("SUBDOMAINS DISCOVERED")
        report.append("-" * 80)
        alive_subs = [s for s in scan_result.subdomains if s.is_alive]
        report.append(f"Alive: {len(alive_subs)}")
        for sub in alive_subs:
            report.append(f"  - {sub.full_domain} ({', '.join(sub.ip_addresses)})")
        report.append("")
        report.append("VULNERABILITIES BY SEVERITY")
        report.append("-" * 80)
        if high_count > 0:
            report.append(f"🔴 HIGH: {high_count}")
        if medium_count > 0:
            report.append(f"🟡 MEDIUM: {medium_count}")
        if low_count > 0:
            report.append(f"🟢 LOW: {low_count}")
        report.append("")
        report.append("DETAILED VULNERABILITY REPORT")
        report.append("-" * 80)
        report.append("")
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            severity_vulns = [v for v in scan_result.vulnerabilities if v.severity == severity]
            if severity_vulns:
                report.append(f"{'🔴' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🟢'} {severity} SEVERITY VULNERABILITIES:")
                report.append("-" * 40)
                for i, vuln in enumerate(severity_vulns, 1):
                    report.append("")
                    report.append(f"{i}. {vuln.name}")
                    report.append(f"   Category: {vuln.category}")
                    report.append(f"   CVSS Score: {vuln.cvss_score}")
                    report.append(f"   Confidence: {vuln.confidence * 100:.1f}%")
                    report.append(f"   CWE: {vuln.cwe_id}")
                    report.append(f"   Endpoint: {vuln.endpoint}")
                    report.append(f"   DESCRIPTION: {vuln.description}")
                    report.append(f"   IMPACT: {vuln.impact}")
                    report.append(f"   RECOMMENDATION: {vuln.recommendation}")
                    if vuln.exploitation_steps:
                        report.append(f"   EXPLOITATION STEPS: {vuln.exploitation_steps}")
                    if vuln.payload:
                        report.append(f"   PAYLOAD: {vuln.payload}")
                report.append("")
        return "\n".join(report)
