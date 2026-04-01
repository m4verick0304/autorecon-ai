# AutoReconAI

**AutoReconAI** is an AI-powered cybersecurity tool that automates reconnaissance and suggests relevant exploits based on detected services and versions.

> ⚠️ **For educational and authorised penetration testing use only.** Always obtain written permission before scanning systems you do not own.

---

## Features

- 🔍 **Nmap XML Parser** – Parses `nmap -oX` scan output to extract hosts, ports, services, versions, OS matches and CPEs
- 🎯 **Exploit Recommendation Engine** – Rule-based engine that maps detected services/versions to known CVEs and Metasploit modules
- 🤖 **AI Analysis Layer** – Contextual risk scoring, attack surface assessment, priority findings and actionable remediation suggestions
- 📊 **Flexible Output** – Human-readable text (with ANSI colour) or machine-readable JSON
- 🏗️ **Modular Architecture** – Each component (parser / recommender / AI layer) is independently importable and extensible

---

## Quick Start

### Installation

```bash
git clone https://github.com/m4verick0304/autorecon-ai.git
cd autorecon-ai
pip install -e .
```

### Run a scan analysis

```bash
# Analyse an Nmap XML file (colourised text output)
autorecon sample_scans/sample_nmap.xml

# Machine-readable JSON output
autorecon sample_scans/sample_nmap.xml --format json

# Save results to a file
autorecon scan.xml --format json --output results.json

# Disable colour (useful for piping / logging)
autorecon scan.xml --no-colour
```

### Generate an Nmap XML scan

```bash
# Perform a service + OS detection scan and save to XML
nmap -sV -O -oX scan.xml <target>
```

---

## Project Structure

```
autorecon-ai/
├── autorecon/
│   ├── parser/
│   │   └── nmap_parser.py       # Nmap XML → Host/Service objects
│   ├── recommender/
│   │   ├── vulnerability_db.py  # Static CVE/exploit database
│   │   └── exploit_mapper.py    # Service → ExploitMatch engine
│   ├── ai/
│   │   └── analyzer.py          # Risk scoring & contextual analysis
│   └── cli.py                   # Command-line interface
├── tests/                       # Pytest test suite
├── sample_scans/
│   └── sample_nmap.xml          # Example scan for demo/testing
├── requirements.txt
└── setup.py
```

---

## Python API

```python
from autorecon.parser import NmapParser
from autorecon.recommender import ExploitMapper
from autorecon.ai import AIAnalyzer

# 1. Parse scan output
hosts = NmapParser().parse_file("scan.xml")

# 2. Map services to known exploits
matches = ExploitMapper().map_hosts(hosts)

# 3. AI-assisted analysis
report = AIAnalyzer().analyze(hosts, matches)

print(f"Risk level : {report.risk_level}")
print(f"Score      : {report.attack_surface_score}")
for finding in report.priority_findings:
    print(finding)
```

---

## Vulnerability Coverage

The built-in database covers (among others):

| Service | Notable CVEs |
|---------|-------------|
| SSH | CVE-2018-10933 (libssh bypass), CVE-2023-38408 (ssh-agent RCE) |
| FTP | CVE-2011-2523 (vsftpd backdoor), CVE-2010-4221 (ProFTPD RCE) |
| HTTP/HTTPS | CVE-2021-41773/42013 (Apache path traversal), CVE-2014-6271 (Shellshock), CVE-2014-0160 (Heartbleed) |
| SMB | CVE-2017-0144 (EternalBlue), CVE-2020-0796 (SMBGhost), CVE-2021-34527 (PrintNightmare) |
| RDP | CVE-2019-0708 (BlueKeep), CVE-2019-1181 (DejaBlue) |
| MySQL | CVE-2012-2122 (auth bypass), CVE-2016-6662 (RCE) |
| Redis / MongoDB | Unauthenticated access detection |
| Telnet / SNMP | Cleartext / default-credential detection |

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
# With coverage
pytest tests/ --cov=autorecon --cov-report=term-missing
```

---

## Tech Stack

- **Python 3.8+** – stdlib only for core engine (no heavy ML dependencies required)
- **Rule-based AI layer** – Extensible to LLM-based reasoning (OpenAI, local LLaMA, etc.)
- **pytest** – Test suite

---

## Contributing

Contributions welcome! Areas for enhancement:
- CVE database integration (NVD API)
- Metasploit RPC module launching
- LLM-based contextual reasoning
- Web/dashboard frontend (JavaScript)
- Additional scan format parsers (Masscan, Shodan JSON)

Please open an issue or pull request.
