"""AI/rule-based analysis layer.

Provides contextual analysis of scan results, including:
- Attack surface scoring
- Risk summary generation
- Prioritised remediation suggestions

This module uses rule-based heuristics and can be extended to integrate with
LLM-based reasoning (OpenAI, local LLaMA, etc.) for smarter suggestions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from autorecon.parser.nmap_parser import Host
from autorecon.recommender.exploit_mapper import ExploitMatch

# ---------------------------------------------------------------------------
# Severity weights used for attack surface scoring
# ---------------------------------------------------------------------------
_SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}

# Ports/services that indicate elevated exposure even without a matched vuln
_HIGH_RISK_PORTS = {21, 23, 69, 111, 512, 513, 514, 2049, 3389, 5900, 6379, 27017}
_CLEARTEXT_SERVICES = {"ftp", "telnet", "http", "snmp", "ldap"}


@dataclass
class AnalysisReport:
    """Full analysis report for a set of scanned hosts."""

    hosts: List[Host]
    matches: List[ExploitMatch]
    attack_surface_score: int = 0
    risk_level: str = "low"
    summary: str = ""
    remediation_suggestions: List[str] = field(default_factory=list)
    priority_findings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os_matches": h.os_matches,
                    "open_ports": [
                        {
                            "port": s.port,
                            "protocol": s.protocol,
                            "service": s.name,
                            "version": s.version_string,
                        }
                        for s in h.open_services
                    ],
                }
                for h in self.hosts
            ],
            "vulnerability_matches": [
                {
                    "host": m.host_ip,
                    "port": m.port,
                    "service": m.service_name,
                    "cve": m.vuln.cve,
                    "severity": m.vuln.severity,
                    "description": m.vuln.description,
                    "exploit_refs": m.vuln.exploit_refs,
                }
                for m in self.matches
            ],
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "remediation_suggestions": self.remediation_suggestions,
            "priority_findings": self.priority_findings,
        }


class AIAnalyzer:
    """Analyse scan results and produce a contextual :class:`AnalysisReport`.

    This class implements a rule-based heuristic engine that can be extended
    to use LLM-based reasoning.  The public ``analyze`` method is the main
    entry point.

    Args:
        verbose: If ``True``, include additional debug details in the report.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, hosts: List[Host], matches: List[ExploitMatch]) -> AnalysisReport:
        """Perform contextual analysis and return an :class:`AnalysisReport`.

        Args:
            hosts: Scanned hosts (from the parser engine).
            matches: Exploit matches (from the recommendation engine).

        Returns:
            A fully populated :class:`AnalysisReport`.
        """
        score = self._calculate_score(hosts, matches)
        risk_level = self._score_to_risk(score)
        priority_findings = self._extract_priority_findings(matches)
        remediation = self._generate_remediation(hosts, matches)
        summary = self._generate_summary(hosts, matches, risk_level, score)

        return AnalysisReport(
            hosts=hosts,
            matches=matches,
            attack_surface_score=score,
            risk_level=risk_level,
            summary=summary,
            remediation_suggestions=remediation,
            priority_findings=priority_findings,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_score(self, hosts: List[Host], matches: List[ExploitMatch]) -> int:
        """Calculate a numeric attack-surface score."""
        score = 0

        # Contribution from matched vulnerabilities
        for match in matches:
            score += _SEVERITY_WEIGHTS.get(match.vuln.severity.lower(), 1)

        # Contribution from open high-risk ports (even without a vuln match)
        matched_ports = {(m.host_ip, m.port) for m in matches}
        for host in hosts:
            for svc in host.open_services:
                if svc.port in _HIGH_RISK_PORTS and (host.ip, svc.port) not in matched_ports:
                    score += 3

        # Contribution from cleartext services
        for host in hosts:
            for svc in host.open_services:
                if svc.name.lower() in _CLEARTEXT_SERVICES:
                    score += 1

        return score

    @staticmethod
    def _score_to_risk(score: int) -> str:
        """Convert numeric score to a categorical risk level."""
        if score >= 30:
            return "critical"
        if score >= 15:
            return "high"
        if score >= 5:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Findings & remediation
    # ------------------------------------------------------------------

    def _extract_priority_findings(self, matches: List[ExploitMatch]) -> List[str]:
        """Return a deduplicated list of the most critical findings."""
        findings: List[str] = []
        seen: set = set()
        for match in matches:
            if match.vuln.severity.lower() in ("critical", "high"):
                key = (match.host_ip, match.vuln.cve)
                if key not in seen:
                    findings.append(match.summary())
                    seen.add(key)
        return findings

    def _generate_remediation(
        self, hosts: List[Host], matches: List[ExploitMatch]
    ) -> List[str]:
        """Generate actionable remediation suggestions."""
        suggestions: List[str] = []
        seen: set = set()

        # Vuln-specific suggestions
        for match in matches:
            if match.vuln.cve not in seen:
                seen.add(match.vuln.cve)
                ref = match.vuln.exploit_refs[0] if match.vuln.exploit_refs else ""
                suggestion = f"Patch {match.vuln.cve} ({match.vuln.description[:60]})"
                if ref:
                    suggestion += f" — see: {ref}"
                suggestions.append(suggestion)

        # General suggestions based on open services
        for host in hosts:
            for svc in host.open_services:
                svc_lower = svc.name.lower()
                if svc_lower == "telnet" and "TELNET-disable" not in seen:
                    suggestions.append("Disable Telnet; replace with SSH for encrypted remote access")
                    seen.add("TELNET-disable")
                if svc_lower == "ftp" and "FTP-secure" not in seen:
                    suggestions.append("Replace FTP with SFTP/FTPS to prevent cleartext credential exposure")
                    seen.add("FTP-secure")
                if svc_lower == "snmp" and "SNMP-harden" not in seen:
                    suggestions.append("Change SNMP community strings from defaults and restrict access by IP")
                    seen.add("SNMP-harden")
                if svc.port == 3389 and "RDP-restrict" not in seen:
                    suggestions.append("Restrict RDP access via VPN/firewall rules; enable NLA authentication")
                    seen.add("RDP-restrict")
                if svc_lower in ("mongodb", "redis", "elasticsearch") and f"{svc_lower}-auth" not in seen:
                    suggestions.append(
                        f"Enable authentication on {svc.name} and bind it to localhost or trusted IPs only"
                    )
                    seen.add(f"{svc_lower}-auth")

        return suggestions

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    def _generate_summary(
        self,
        hosts: List[Host],
        matches: List[ExploitMatch],
        risk_level: str,
        score: int,
    ) -> str:
        """Generate a concise natural-language summary of the analysis."""
        total_hosts = len(hosts)
        total_open = sum(len(h.open_services) for h in hosts)
        critical_count = sum(1 for m in matches if m.vuln.severity.lower() == "critical")
        high_count = sum(1 for m in matches if m.vuln.severity.lower() == "high")

        lines = [
            f"Scan analysed {total_hosts} host(s) with {total_open} open service(s).",
            f"Found {len(matches)} potential vulnerability match(es) "
            f"({critical_count} critical, {high_count} high).",
            f"Overall risk level: {risk_level.upper()} (attack surface score: {score}).",
        ]

        if risk_level in ("critical", "high"):
            lines.append(
                "Immediate action recommended: review priority findings and apply patches."
            )
        elif risk_level == "medium":
            lines.append("Moderate risk: schedule remediation for identified vulnerabilities.")
        else:
            lines.append("Low risk: no critical vulnerabilities detected in current scan.")

        return " ".join(lines)
