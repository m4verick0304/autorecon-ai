"""Tests for the Nmap XML parser."""

import textwrap
import pytest

from autorecon.parser.nmap_parser import NmapParser, Host, Service


# ---------------------------------------------------------------------------
# Minimal valid Nmap XML fixture
# ---------------------------------------------------------------------------
MINIMAL_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="test.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.2p2"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="closed"/>
            <service name="http"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

MULTI_HOST_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open"/>
            <service name="ftp" product="vsftpd" version="2.3.4"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="up"/>
        <address addr="10.0.0.2" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="3306">
            <state state="open"/>
            <service name="mysql" product="MySQL" version="5.5.62"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

OS_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <hostnames/>
        <ports/>
        <os>
          <osmatch name="Linux 4.15" accuracy="95"/>
          <osmatch name="Linux 5.x" accuracy="80"/>
        </os>
      </host>
    </nmaprun>
""")

CPE_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.6" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="Apache httpd" version="2.4.49">
              <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
            </service>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


class TestNmapParserBasics:
    def setup_method(self):
        self.parser = NmapParser()

    def test_parse_string_returns_hosts(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        assert len(hosts) == 1

    def test_host_ip_extracted(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        assert hosts[0].ip == "10.0.0.1"

    def test_hostname_extracted(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        assert hosts[0].hostname == "test.local"

    def test_host_status(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        assert hosts[0].status == "up"

    def test_services_parsed(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        assert len(hosts[0].services) == 2

    def test_open_services_only(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        open_svcs = hosts[0].open_services
        assert len(open_svcs) == 1
        assert open_svcs[0].port == 22

    def test_service_fields(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        svc = hosts[0].services[0]
        assert svc.port == 22
        assert svc.protocol == "tcp"
        assert svc.state == "open"
        assert svc.name == "ssh"
        assert svc.product == "OpenSSH"
        assert svc.version == "7.2p2"

    def test_service_version_string(self):
        hosts = self.parser.parse_string(MINIMAL_XML)
        svc = hosts[0].services[0]
        assert "OpenSSH" in svc.version_string
        assert "7.2p2" in svc.version_string


class TestNmapParserMultiHost:
    def setup_method(self):
        self.parser = NmapParser()

    def test_multiple_hosts_parsed(self):
        hosts = self.parser.parse_string(MULTI_HOST_XML)
        assert len(hosts) == 2

    def test_host_ips(self):
        hosts = self.parser.parse_string(MULTI_HOST_XML)
        ips = {h.ip for h in hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}


class TestNmapParserOS:
    def setup_method(self):
        self.parser = NmapParser()

    def test_os_matches_extracted(self):
        hosts = self.parser.parse_string(OS_XML)
        assert "Linux 4.15" in hosts[0].os_matches

    def test_multiple_os_matches(self):
        hosts = self.parser.parse_string(OS_XML)
        assert len(hosts[0].os_matches) == 2


class TestNmapParserCPE:
    def setup_method(self):
        self.parser = NmapParser()

    def test_cpe_extracted(self):
        hosts = self.parser.parse_string(CPE_XML)
        svc = hosts[0].services[0]
        assert "cpe:/a:apache:http_server:2.4.49" in svc.cpe


class TestNmapParserErrors:
    def setup_method(self):
        self.parser = NmapParser()

    def test_invalid_xml_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid XML"):
            self.parser.parse_string("this is not xml <<<")

    def test_wrong_root_element_raises_value_error(self):
        with pytest.raises(ValueError, match="nmaprun"):
            self.parser.parse_string("<root><child/></root>")

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            self.parser.parse_file(tmp_path / "nonexistent.xml")

    def test_parse_file_reads_file(self, tmp_path):
        xml_file = tmp_path / "scan.xml"
        xml_file.write_text(MINIMAL_XML, encoding="utf-8")
        hosts = self.parser.parse_file(xml_file)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"

    def test_empty_nmaprun(self):
        xml = '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"/>'
        hosts = self.parser.parse_string(xml)
        assert hosts == []

    def test_host_without_address_skipped(self):
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun scanner="nmap" version="7.94">
              <host>
                <status state="up"/>
                <hostnames/>
                <ports/>
              </host>
            </nmaprun>
        """)
        hosts = self.parser.parse_string(xml)
        assert hosts == []
