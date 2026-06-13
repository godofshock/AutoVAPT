<div align="center">

```
 █████╗ ██╗   ██╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ████████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
███████║██║   ██║   ██║   ██║   ██║██║   ██║███████║██████╔╝   ██║   
██╔══██║██║   ██║   ██║   ██║   ██║╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   
██║  ██║╚██████╔╝   ██║   ╚██████╔╝ ╚████╔╝ ██║  ██║██║        ██║   
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   
```

**Automated Vulnerability Assessment & Penetration Testing Framework**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/godofshock/AutoVAPT/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/codecov/c/github/yourusername/AutoVAPT)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> **AutoVAPT** is an end-to-end VAPT automation framework that takes a target scope from input to a client-grade PDF report — performing recon, vulnerability scanning, exploit validation, CVSS-based risk scoring, and report generation with zero manual steps.

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Lab Setup (DVWA + Metasploitable)](#lab-setup)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Overview

AutoVAPT automates the complete VAPT engagement lifecycle:

```
Target Input → Recon → Vulnerability Scan → Exploit Validation → Risk Scoring → PDF Report
```

Each phase feeds directly into the next. The final output is a **client-grade PDF** with an executive summary, colour-coded findings, CVSS v3 scores, composite risk scores, and actionable remediation steps — plus a **machine-readable JSON** artefact for SOC platform ingestion.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────▼───────────────┐
         │       Phase 1 — Recon         │
         │  Nmap · DNS enum · Shodan API │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │    Phase 2 — Vuln Scanner     │◄─── NVD API (live CVE feed)
         │  HTTP · SSH · FTP · SMB ...   │
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │  Phase 3 — Exploit Validator  │◄─── Metasploit RPC / manual PoC
         │  check() → confirm exploitable│
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │    Phase 4 — Risk Scorer      │
         │  CVSS × exploitability × asset│
         └───────────────┬───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │   Phase 5 — Report Generator  │
         │   Executive PDF + JSON        │
         └───────────────────────────────┘
```

---

## Features

| Feature | Description |
|---|---|
| **Full pipeline automation** | Recon to report in one command |
| **Live CVE enrichment** | NVD API v2.0 — real-time CVE mapping per finding |
| **Exploit validation** | Metasploit RPC — confirms exploitability, not just detection |
| **Composite risk scoring** | CVSS × exploitability weight × asset criticality |
| **Multi-service support** | HTTP/S, SSH, FTP, SMB, MySQL, RDP |
| **Professional PDF report** | Executive summary + technical findings + remediation table |
| **JSON output** | Machine-readable for SOC/SIEM ingestion |
| **Configurable intensity** | `low` / `medium` / `high` scan profiles |
| **Shodan integration** | Optional external intelligence enrichment |
| **DNS enumeration** | Subdomain discovery + DNS record mapping |
| **OS fingerprinting** | Via nmap `-O` flag |
| **CI/CD ready** | GitHub Actions: test → lint → pip-audit |

---

## Prerequisites

- **Kali Linux** (recommended) or Debian/Ubuntu
- **Python 3.9+**
- **Nmap** installed and in PATH: `sudo apt install nmap -y`
- **Metasploit Framework** (for exploit validation): `sudo apt install metasploit-framework -y`
- Free **NVD API key** (optional but recommended): https://nvd.nist.gov/developers/request-an-api-key

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/AutoVAPT.git
cd AutoVAPT

# 2. Install Python dependencies
pip install -r requirements.txt --break-system-packages

# 3. (Optional) Set environment variables
export NVD_API_KEY="your_nvd_api_key_here"
export SHODAN_API_KEY="your_shodan_key_here"

# 4. Verify installation
python main.py --version
```

---

## Usage

### Basic full scan
```bash
python main.py --target 192.168.1.10
```

### Recon only
```bash
python main.py --target 192.168.1.0/24 --mode recon
```

### Full scan, high intensity, skip exploit validation
```bash
python main.py --target 10.0.0.5 --mode full --intensity high --skip-exploit
```

### Custom output directory and JSON only
```bash
python main.py --target example.local --output /tmp/reports --format json
```

### Verbose with custom config
```bash
python main.py --target 192.168.1.10 --config my_config.yaml --verbose
```

### All options
```
usage: AutoVAPT [-h] --target TARGET [--mode {recon,scan,full}]
                [--output OUTPUT] [--format {pdf,json,both}]
                [--skip-exploit] [--intensity {low,medium,high}]
                [--config CONFIG] [--verbose]

Options:
  --target, -t       Target IP, domain, or CIDR range
  --mode, -m         recon | scan | full  (default: full)
  --output, -o       Report output directory (default: ./reports)
  --format, -f       pdf | json | both    (default: both)
  --skip-exploit     Skip Metasploit exploit validation phase
  --intensity        low | medium | high  (default: medium)
  --config           Path to config.yaml  (default: config.yaml)
  --verbose, -v      Enable verbose/debug output
```

---

## Output

After a successful scan, two files are created in `./reports/`:

```
reports/
├── autovapt_20240101_120000.pdf    ← Client-grade PDF report
└── autovapt_20240101_120000.json   ← Raw findings (SOC/SIEM format)
```

### PDF Report sections:
1. **Cover page** — Target, date, overall risk rating badge
2. **Executive Summary** — Finding counts by severity, top 3 risks, recon stats
3. **Vulnerability Findings** — Full details per finding: CVSS, composite score, evidence, remediation
4. **Remediation Summary** — Prioritised table for remediation tracking
5. **Appendix A** — Raw recon data: ports, services, DNS records

### Sample JSON structure:
```json
{
  "scan_id": "20240101_120000",
  "target": "192.168.1.10",
  "summary": {
    "overall_risk": "HIGH",
    "total": 12,
    "critical": 1,
    "high": 3,
    "medium": 6,
    "low": 2
  },
  "risk_scores": [
    {
      "title": "EternalBlue (MS17-010)",
      "cvss_score": 9.8,
      "composite_score": 10.0,
      "risk_level": "CRITICAL",
      "exploit_status": "CONFIRMED",
      "cve_ids": ["CVE-2017-0144"],
      "remediation": "Apply MS17-010 patch immediately..."
    }
  ]
}
```

---

## Lab Setup

AutoVAPT is designed for use against intentionally vulnerable targets. **Never test against systems you don't own.**

### Recommended test environment (VirtualBox)

```
┌─────────────────────┐    Host-Only Network     ┌──────────────────────┐
│   Kali Linux        │◄────────────────────────►│  Metasploitable 2    │
│   (attacker)        │    192.168.56.0/24        │  192.168.56.101      │
│   AutoVAPT runs here│                           │  (target)            │
└─────────────────────┘                           └──────────────────────┘
                                                  ┌──────────────────────┐
                                                  │   DVWA               │
                                                  │   192.168.56.102     │
                                                  │   (web target)       │
                                                  └──────────────────────┘
```

### Quick setup:
```bash
# Download Metasploitable 2
# https://sourceforge.net/projects/metasploitable/

# Download DVWA via Docker
docker run -d -p 80:80 vulnerables/web-dvwa

# Start Metasploit RPC daemon (required for exploit validation)
msfrpcd -P msf -S -f -a 127.0.0.1
```

---

## Configuration

Edit `config.yaml` to customise scan behaviour:

```yaml
nmap:
  timing: T3         # T2 = polite, T3 = normal, T4 = aggressive
  top_ports: 1000

nvd_api:
  api_key: ""        # Set NVD_API_KEY env var instead

metasploit:
  host: "127.0.0.1"
  port: 55553
  password: "msf"    # Change this

risk:
  asset_criticality: "high"   # low | medium | high | critical
```

---

## Project Structure

```
AutoVAPT/
├── main.py                          # CLI entry point
├── config.yaml                      # Default configuration
├── requirements.txt
├── setup.py
├── LICENSE
├── README.md
│
├── autovapt/
│   ├── __init__.py
│   ├── modules/
│   │   ├── recon.py                 # Phase 1: Nmap, DNS, Shodan
│   │   ├── scanner.py               # Phase 2: Vuln checks + NVD CVE mapping
│   │   ├── exploit_validator.py     # Phase 3: Metasploit RPC validation
│   │   ├── risk_scorer.py           # Phase 4: CVSS composite scoring
│   │   └── report_generator.py      # Phase 5: PDF + JSON output
│   └── utils/
│       ├── config.py                # YAML config manager
│       ├── logger.py                # Coloured console + file logger
│       ├── nvd_client.py            # NVD API v2.0 client
│       └── banner.py                # ASCII banner
│
├── tests/
│   └── test_autovapt.py             # pytest unit + integration tests
│
├── reports/                         # Generated reports (gitignored)
├── logs/                            # Scan logs (gitignored)
│
└── .github/
    └── workflows/
        └── ci.yml                   # GitHub Actions: test + lint + audit
```

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov --break-system-packages

# Run full test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=autovapt --cov-report=term-missing

# Run a specific test class
pytest tests/test_autovapt.py::TestRiskScorer -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for any new functionality
4. Ensure all tests pass: `pytest tests/ -v`
5. Submit a pull request against `develop`

---

## Disclaimer

> **AutoVAPT is strictly for authorized security testing and educational purposes.**
> Using this tool against any system without explicit written permission from the system owner is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws worldwide.
> The author assumes **no liability** for any misuse of this software.
> Always obtain written authorization before conducting any security assessment.

---

<div align="center">
Built with ❤️ for the security community · <a href="https://github.com/yourusername/AutoVAPT/issues">Report a Bug</a> · <a href="https://github.com/yourusername/AutoVAPT/issues">Request a Feature</a>
</div>
