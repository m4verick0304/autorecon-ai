"""Tests for the CLI entry point."""

import json
import textwrap
from pathlib import Path

import pytest

from autorecon.cli import build_parser, run


MINIMAL_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.2p2"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

RICH_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <hostnames>
          <hostname name="target.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open"/>
            <service name="ftp" product="vsftpd" version="2.3.4"/>
          </port>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="smb"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 4.15" accuracy="95"/>
        </os>
      </host>
    </nmaprun>
""")


@pytest.fixture
def minimal_scan(tmp_path):
    f = tmp_path / "scan.xml"
    f.write_text(MINIMAL_XML, encoding="utf-8")
    return f


@pytest.fixture
def rich_scan(tmp_path):
    f = tmp_path / "rich_scan.xml"
    f.write_text(RICH_XML, encoding="utf-8")
    return f


class TestCLIParser:
    def test_build_parser_returns_argparse(self):
        p = build_parser()
        assert p is not None

    def test_default_format_is_text(self, minimal_scan):
        p = build_parser()
        ns = p.parse_args([str(minimal_scan)])
        assert ns.format == "text"

    def test_json_format_flag(self, minimal_scan):
        p = build_parser()
        ns = p.parse_args([str(minimal_scan), "--format", "json"])
        assert ns.format == "json"

    def test_no_colour_flag(self, minimal_scan):
        p = build_parser()
        ns = p.parse_args([str(minimal_scan), "--no-colour"])
        assert ns.no_colour is True

    def test_verbose_flag(self, minimal_scan):
        p = build_parser()
        ns = p.parse_args([str(minimal_scan), "--verbose"])
        assert ns.verbose is True


class TestCLIRun:
    def test_run_returns_zero_on_success(self, minimal_scan, capsys):
        rc = run([str(minimal_scan), "--no-colour"])
        assert rc == 0

    def test_run_returns_one_on_missing_file(self, tmp_path, capsys):
        rc = run([str(tmp_path / "nonexistent.xml")])
        assert rc == 1

    def test_run_returns_one_on_invalid_xml(self, tmp_path, capsys):
        bad = tmp_path / "bad.xml"
        bad.write_text("not xml <<<", encoding="utf-8")
        rc = run([str(bad)])
        assert rc == 1

    def test_run_text_output_contains_ip(self, minimal_scan, capsys):
        run([str(minimal_scan), "--no-colour"])
        captured = capsys.readouterr()
        assert "10.0.0.1" in captured.out

    def test_run_text_output_contains_service(self, minimal_scan, capsys):
        run([str(minimal_scan), "--no-colour"])
        captured = capsys.readouterr()
        assert "22" in captured.out or "ssh" in captured.out.lower()

    def test_run_json_output_is_valid(self, minimal_scan, capsys):
        run([str(minimal_scan), "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "hosts" in data
        assert data["hosts"][0]["ip"] == "10.0.0.1"

    def test_run_json_has_vulnerability_matches(self, rich_scan, capsys):
        run([str(rich_scan), "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "vulnerability_matches" in data
        assert len(data["vulnerability_matches"]) > 0

    def test_run_output_to_file(self, minimal_scan, tmp_path, capsys):
        out_file = tmp_path / "results.json"
        rc = run([str(minimal_scan), "--format", "json", "--output", str(out_file)])
        assert rc == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "hosts" in data

    def test_run_text_output_to_file(self, rich_scan, tmp_path, capsys):
        out_file = tmp_path / "results.txt"
        rc = run([str(rich_scan), "--no-colour", "--output", str(out_file)])
        assert rc == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_run_rich_scan_has_critical_findings(self, rich_scan, capsys):
        run([str(rich_scan), "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        severities = [m["severity"] for m in data["vulnerability_matches"]]
        assert "critical" in severities

    def test_sample_scan_from_repo(self, capsys):
        """Smoke test using the bundled sample scan."""
        sample = Path(__file__).parent.parent / "sample_scans" / "sample_nmap.xml"
        if not sample.exists():
            pytest.skip("sample_scans/sample_nmap.xml not found")
        rc = run([str(sample), "--format", "json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data["hosts"]) >= 1
        assert len(data["vulnerability_matches"]) > 0
