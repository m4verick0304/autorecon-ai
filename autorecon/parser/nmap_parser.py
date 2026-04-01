"""Nmap XML scan output parser.

Parses Nmap XML reports and extracts structured host and service information
for use by the recommendation and AI analysis engines.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Service:
    """Represents a single network service discovered on a host."""

    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: List[str] = field(default_factory=list)

    @property
    def version_string(self) -> str:
        """Return a human-readable service/version string."""
        parts = [p for p in (self.product, self.version, self.extra_info) if p]
        return " ".join(parts) if parts else self.name

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"{self.port}/{self.protocol} {self.state} {self.name}"
            + (f" ({self.version_string})" if self.version_string != self.name else "")
        )


@dataclass
class Host:
    """Represents a scanned host with its discovered services."""

    ip: str
    hostname: str = ""
    os_matches: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    status: str = "up"

    @property
    def open_services(self) -> List[Service]:
        """Return only the services in 'open' state."""
        return [s for s in self.services if s.state == "open"]

    def __str__(self) -> str:  # pragma: no cover
        return f"Host({self.ip}, hostname={self.hostname!r}, services={len(self.services)})"


class NmapParser:
    """Parse Nmap XML output files or strings into structured Host objects."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, path: str | Path) -> List[Host]:
        """Parse an Nmap XML file and return a list of :class:`Host` objects.

        Args:
            path: Path to the Nmap XML output file.

        Returns:
            List of :class:`Host` objects found in the scan.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not valid Nmap XML.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found: {path}")
        return self.parse_string(path.read_text(encoding="utf-8"))

    def parse_string(self, xml_content: str) -> List[Host]:
        """Parse Nmap XML content from a string.

        Args:
            xml_content: Raw XML string produced by ``nmap -oX``.

        Returns:
            List of :class:`Host` objects.

        Raises:
            ValueError: If the content is not valid Nmap XML.
        """
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML content: {exc}") from exc

        if root.tag != "nmaprun":
            raise ValueError(
                f"Expected root element 'nmaprun', got '{root.tag}'. "
                "Is this an Nmap XML file?"
            )

        hosts: List[Host] = []
        for host_elem in root.findall("host"):
            host = self._parse_host(host_elem)
            if host is not None:
                hosts.append(host)
        return hosts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_host(self, host_elem: ET.Element) -> Optional[Host]:
        """Parse a single <host> element."""
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        # Extract IP address
        ip = ""
        hostname = ""
        for addr_elem in host_elem.findall("address"):
            addr_type = addr_elem.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6"):
                ip = addr_elem.get("addr", "")

        if not ip:
            return None

        # Extract hostnames
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn_elem in hostnames_elem.findall("hostname"):
                name = hn_elem.get("name", "")
                if name:
                    hostname = name
                    break

        # Extract OS guesses
        os_matches: List[str] = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for match_elem in os_elem.findall("osmatch"):
                os_name = match_elem.get("name", "")
                if os_name:
                    os_matches.append(os_name)

        # Extract services (ports)
        services = self._parse_ports(host_elem)

        return Host(
            ip=ip,
            hostname=hostname,
            os_matches=os_matches,
            services=services,
            status=status,
        )

    def _parse_ports(self, host_elem: ET.Element) -> List[Service]:
        """Parse all <port> elements within a <ports> section."""
        services: List[Service] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            return services

        for port_elem in ports_elem.findall("port"):
            service = self._parse_port(port_elem)
            if service is not None:
                services.append(service)
        return services

    def _parse_port(self, port_elem: ET.Element) -> Optional[Service]:
        """Parse a single <port> element."""
        try:
            port_num = int(port_elem.get("portid", "0"))
        except ValueError:
            return None
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        service_elem = port_elem.find("service")
        name = ""
        product = ""
        version = ""
        extra_info = ""
        cpe_list: List[str] = []

        if service_elem is not None:
            name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            extra_info = service_elem.get("extrainfo", "")
            for cpe_elem in service_elem.findall("cpe"):
                if cpe_elem.text:
                    cpe_list.append(cpe_elem.text.strip())

        return Service(
            port=port_num,
            protocol=protocol,
            state=state,
            name=name,
            product=product,
            version=version,
            extra_info=extra_info,
            cpe=cpe_list,
        )
