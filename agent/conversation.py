"""
Cybersecurity Agent - Conversational interface for security analysis.
"""

import re
import json
from typing import Dict, Optional, Any, List
from datetime import datetime

from .memory import ConversationMemory
from analysis import (
    ThreatDetector,
    LogAnalyzer,
    VulnerabilityScanner,
    WebScanner,
    FullSiteScanner
)

class CyberSecurityAgent:
    """
    A conversational cybersecurity analyst agent.
    """

    def __init__(self):
        self.memory = ConversationMemory()
        self.tools = {
            "threat_detector": ThreatDetector(),
            "log_analyzer": LogAnalyzer(),
            "vulnerability_scanner": VulnerabilityScanner(),
            "web_scanner": WebScanner(),
            "full_site_scanner": FullSiteScanner()
        }
        self.name = "CyberSecurityAgent"
        self.version = "2.0.0"

    def _analyze_intent(self, message: str) -> Dict[str, Any]:
        """
        Analyze user message to determine intent.
        """
        message_lower = message.lower()
        intent = "unknown"
        entities = {}

        # Intent detection
        if any(word in message_lower for word in ["scan website", "scan site", "scan my site", "scan this site"]):
            intent = "scan_website"
        elif any(word in message_lower for word in ["scan full", "full scan", "scan all", "deep scan"]):
            intent = "scan_full_site"
        elif any(word in message_lower for word in ["analyze logs", "check logs", "log analysis"]):
            intent = "analyze_logs"
        elif any(word in message_lower for word in ["detect threats", "check threats", "threat detection"]):
            intent = "detect_threats"
        elif any(word in message_lower for word in ["scan vulnerabilities", "check cve", "vulnerability scan"]):
            intent = "scan_vulnerabilities"
        elif any(word in message_lower for word in ["what is", "explain", "how to", "tell me", "?"]):
            intent = "answer_question"
        elif any(word in message_lower for word in ["incident", "breach", "attack", "handle incident"]):
            intent = "handle_incident"
        elif any(word in message_lower for word in ["recommend", "advice", "best practices", "how to fix"]):
            intent = "provide_recommendations"

        # Entity extraction
        entities["url"] = self._extract_url(message)
        entities["ip"] = self._extract_ip(message)
        entities["cve"] = self._extract_cve(message)
        entities["hash"] = self._extract_hash(message)

        return {"intent": intent, "entities": entities}

    def _extract_url(self, message: str) -> Optional[str]:
        """
        Extract URL from message.
        """
        url_pattern = r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-._~:/?#[\]@!$&()*+,;=]+)'
        match = re.search(url_pattern, message, re.IGNORECASE)
        if match:
            url = match.group(1)
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'https://' + url
            return url
        # Try to match domain without protocol
        domain_pattern = r'(?:^|\s)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)(?:$|\s|/|:)'
        match = re.search(domain_pattern, message, re.IGNORECASE)
        if match:
            domain = match.group(1)
            return f"https://{domain}"
        return None

    def _extract_ip(self, message: str) -> Optional[str]:
        """
        Extract IP address from message.
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None

    def _extract_cve(self, message: str) -> Optional[str]:
        """
        Extract CVE ID from message.
        """
        cve_pattern = r'CVE-\d{4}-\d+'
        match = re.search(cve_pattern, message)
        return match.group(0) if match else None

    def _extract_hash(self, message: str) -> Optional[str]:
        """
        Extract hash from message.
        """
        hash_patterns = [
            r'[a-fA-F0-9]{32}',  # MD5
            r'[a-fA-F0-9]{40}',  # SHA-1
            r'[a-fA-F0-9]{64}',  # SHA-256
        ]
        for pattern in hash_patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(0)
        return None

    def chat(self, message: str) -> str:
        """
        Process a user message and return a response.
        """
        self.memory.add_message("user", message)
        intent_info = self._analyze_intent(message)
        intent = intent_info["intent"]
        entities = intent_info["entities"]

        response = self._route_message(message, intent, entities)
        self.memory.add_message("assistant", response)
        return response

    def _route_message(self, message: str, intent: str, entities: Dict) -> str:
        """
        Route message to appropriate handler.
        """
        handlers = {
            "scan_website": self._handle_website_scan,
            "scan_full_site": self._handle_full_site_scan,
            "analyze_logs": self._handle_log_analysis,
            "detect_threats": self._handle_threat_detection,
            "scan_vulnerabilities": self._handle_vulnerability_scan,
            "answer_question": self._handle_question,
            "handle_incident": self._handle_incident,
            "provide_recommendations": self._handle_recommendations,
            "unknown": self._handle_unknown,
        }

        handler = handlers.get(intent, handlers["unknown"])
        return handler(message, entities)

    def _handle_website_scan(self, message: str, entities: Dict) -> str:
        """
        Handle website scan request.
        """
        url = entities.get("url")
        if not url:
            url = self._extract_url(message)
        if not url:
            return "Please provide a website URL to scan..."

        scanner = self.tools["web_scanner"]
        scan_result = scanner.scan(url, deep=True)
        return self._format_web_scan_report(scan_result)

    def _handle_full_site_scan(self, message: str, entities: Dict) -> str:
        """
        Handle full site scan request.
        """
        url = entities.get("url")
        if not url:
            url = self._extract_url(message)
        if not url:
            return "Please provide a website URL to scan..."

        domain = self._normalize_domain(url)
        scanner = self.tools["full_site_scanner"]
        scan_result = scanner.scan(domain, deep=True)
        report = scanner.generate_report(scan_result, output_format="text")
        return report

    def _normalize_domain(self, url: str) -> str:
        """
        Normalize URL to domain format.
        """
        url = url.strip()
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def _format_web_scan_report(self, scan_result: Any) -> str:
        """
        Format web scan result for display.
        """
        report = []
        report.append("=" * 60)
        report.append("WEBSITE SECURITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"URL: {scan_result.url}")
        report.append(f"Scan Time: {scan_result.scan_time}")
        report.append("")
        report.append(f"Vulnerabilities Found: {len(scan_result.vulnerabilities)}")
        for vuln in scan_result.vulnerabilities:
            report.append(f"  - {vuln.name} ({vuln.severity})")
        report.append("")
        report.append(f"Security Headers: {'✓' if scan_result.security_headers else '✗'}")
        report.append(f"SSL Valid: {'✓' if scan_result.ssl_valid else '✗'}")
        return "\n".join(report)

    def _handle_log_analysis(self, message: str, entities: Dict) -> str:
        """
        Handle log analysis request.
        """
        analyzer = self.tools["log_analyzer"]
        logs = message
        if "log:" in message.lower():
            logs = message.split("log:")[-1].strip()
        result = analyzer.analyze(logs)
        return f"Log Analysis Results:\n{json.dumps(result, indent=2)}"

    def _handle_threat_detection(self, message: str, entities: Dict) -> str:
        """
        Handle threat detection request.
        """
        detector = self.tools["threat_detector"]
        text = message
        if "text:" in message.lower():
            text = message.split("text:")[-1].strip()
        result = detector.detect_threats(text)
        return f"Threat Detection Results:\n{json.dumps(result, indent=2)}"

    def _handle_vulnerability_scan(self, message: str, entities: Dict) -> str:
        """
        Handle vulnerability scan request.
        """
        scanner = self.tools["vulnerability_scanner"]
        cve = entities.get("cve")
        if not cve:
            cve = self._extract_cve(message)
        if cve:
            result = scanner.search_cve(cve)
            return f"CVE {cve} Details:\n{json.dumps(result, indent=2)}"
        return "Please provide a CVE ID (e.g., CVE-2021-1234)"

    def _handle_question(self, message: str, entities: Dict) -> str:
        """
        Handle question.
        """
        from knowledge.knowledge_base import CyberSecurityKnowledgeBase
        kb = CyberSecurityKnowledgeBase()
        return kb.answer_question(message)

    def _handle_incident(self, message: str, entities: Dict) -> str:
        """
        Handle incident.
        """
        return f"I'm handling the incident: {message}. Please provide more details about the security incident."

    def _handle_recommendations(self, message: str, entities: Dict) -> str:
        """
        Handle recommendations request.
        """
        return "Security Recommendations:\n1. Keep all software updated\n2. Use strong passwords\n3. Enable multi-factor authentication\n4. Regularly scan for vulnerabilities\n5. Monitor logs for suspicious activity"

    def _handle_unknown(self, message: str, entities: Dict) -> str:
        """
        Handle unknown intent.
        """
        return f"I'm not sure how to help with that. Try asking about cybersecurity, scanning a website, or checking for vulnerabilities."
