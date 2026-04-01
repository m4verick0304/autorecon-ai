"""Tests for the AI analysis layer."""

import pytest

from autorecon.parser.nmap_parser import Host, Service
from autorecon.recommender.exploit_mapper import ExploitMapper
from autorecon.ai.analyzer import AIAnalyzer, AnalysisReport


def _make_service(port, name, product="", version="", state="open", protocol="tcp"):
    return Service(
        port=port, protocol=protocol, state=state,
        name=name, product=product, version=version,
    )


def _make_host(ip, services):
    return Host(ip=ip, services=services)


class TestAIAnalyzer:
    def setup_method(self):
        self.analyzer = AIAnalyzer()
        self.mapper = ExploitMapper()

    def _analyze(self, hosts):
        matches = self.mapper.map_hosts(hosts)
        return self.analyzer.analyze(hosts, matches)

    def test_returns_analysis_report(self):
        hosts = [_make_host("10.0.0.1", [_make_service(22, "ssh", "OpenSSH", "7.2p2")])]
        report = self._analyze(hosts)
        assert isinstance(report, AnalysisReport)

    def test_report_has_hosts(self):
        hosts = [_make_host("10.0.0.1", [_make_service(22, "ssh")])]
        report = self._analyze(hosts)
        assert len(report.hosts) == 1

    def test_report_has_matches(self):
        hosts = [_make_host("10.0.0.1", [_make_service(21, "ftp", "vsftpd", "2.3.4")])]
        report = self._analyze(hosts)
        assert len(report.matches) > 0

    def test_attack_surface_score_positive_for_vulnerable_host(self):
        hosts = [
            _make_host("10.0.0.1", [
                _make_service(21, "ftp", "vsftpd", "2.3.4"),
                _make_service(22, "ssh", "OpenSSH", "7.2p2"),
                _make_service(80, "http", "Apache httpd", "2.4.49"),
            ])
        ]
        report = self._analyze(hosts)
        assert report.attack_surface_score > 0

    def test_risk_level_critical_for_critical_vulns(self):
        hosts = [
            _make_host("10.0.0.1", [
                _make_service(21, "ftp", "vsftpd", "2.3.4"),
                _make_service(80, "http", "Apache httpd", "2.4.49"),
                _make_service(445, "smb"),
                _make_service(3389, "rdp", "Microsoft Terminal Services"),
                _make_service(6379, "redis", "Redis key-value store"),
                _make_service(27017, "mongodb"),
            ])
        ]
        report = self._analyze(hosts)
        assert report.risk_level in ("critical", "high")

    def test_risk_level_low_for_clean_host(self):
        hosts = [_make_host("10.0.0.1", [])]
        report = self._analyze(hosts)
        assert report.risk_level == "low"
        assert report.attack_surface_score == 0

    def test_summary_not_empty(self):
        hosts = [_make_host("10.0.0.1", [_make_service(22, "ssh", "OpenSSH", "7.2p2")])]
        report = self._analyze(hosts)
        assert len(report.summary) > 0

    def test_priority_findings_for_critical(self):
        hosts = [_make_host("10.0.0.1", [_make_service(21, "ftp", "vsftpd", "2.3.4")])]
        report = self._analyze(hosts)
        assert any("CVE-2011-2523" in f for f in report.priority_findings)

    def test_remediation_suggestions_generated(self):
        hosts = [
            _make_host("10.0.0.1", [
                _make_service(23, "telnet"),
                _make_service(21, "ftp", "vsftpd", "2.3.4"),
            ])
        ]
        report = self._analyze(hosts)
        assert len(report.remediation_suggestions) > 0

    def test_remediation_mentions_telnet(self):
        hosts = [_make_host("10.0.0.1", [_make_service(23, "telnet")])]
        report = self._analyze(hosts)
        combined = " ".join(report.remediation_suggestions)
        assert "Telnet" in combined or "telnet" in combined.lower()

    def test_to_dict_structure(self):
        hosts = [_make_host("10.0.0.1", [_make_service(22, "ssh")])]
        report = self._analyze(hosts)
        d = report.to_dict()
        assert "hosts" in d
        assert "vulnerability_matches" in d
        assert "attack_surface_score" in d
        assert "risk_level" in d
        assert "summary" in d
        assert "remediation_suggestions" in d
        assert "priority_findings" in d

    def test_to_dict_hosts_contain_ip(self):
        hosts = [_make_host("10.0.0.1", [_make_service(22, "ssh")])]
        report = self._analyze(hosts)
        d = report.to_dict()
        assert d["hosts"][0]["ip"] == "10.0.0.1"

    def test_to_dict_vulnerability_matches_fields(self):
        hosts = [_make_host("10.0.0.1", [_make_service(21, "ftp", "vsftpd", "2.3.4")])]
        report = self._analyze(hosts)
        d = report.to_dict()
        vm = d["vulnerability_matches"][0]
        assert "host" in vm
        assert "port" in vm
        assert "cve" in vm
        assert "severity" in vm
        assert "description" in vm
        assert "exploit_refs" in vm

    def test_multiple_hosts_analyzed(self):
        hosts = [
            _make_host("10.0.0.1", [_make_service(21, "ftp", "vsftpd", "2.3.4")]),
            _make_host("10.0.0.2", [_make_service(3306, "mysql")]),
        ]
        report = self._analyze(hosts)
        assert len(report.hosts) == 2
        host_ips = {h["ip"] for h in report.to_dict()["hosts"]}
        assert "10.0.0.1" in host_ips
        assert "10.0.0.2" in host_ips

    def test_verbose_flag_accepted(self):
        analyzer = AIAnalyzer(verbose=True)
        hosts = [_make_host("10.0.0.1", [])]
        report = analyzer.analyze(hosts, [])
        assert isinstance(report, AnalysisReport)
