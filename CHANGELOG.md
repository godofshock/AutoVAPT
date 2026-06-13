# Changelog

All notable changes to AutoVAPT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2024

### Added
- **Phase 1 — Recon Engine**: Nmap host/port/service/OS detection, DNS enumeration
  with subdomain brute force, optional Shodan API enrichment
- **Phase 2 — Vulnerability Scanner**: Service-specific checks for HTTP/HTTPS, SSH,
  FTP, SMB, MySQL, RDP; live CVE enrichment via NIST NVD API v2.0
- **Phase 3 — Exploit Validator**: Metasploit RPC integration with check()-first
  safe validation; manual PoC fallback (nmap scripts, direct socket checks)
- **Phase 4 — Risk Scorer**: CVSS v3 × exploitability weight × asset criticality
  composite scoring; overall risk level calculation
- **Phase 5 — Report Generator**: Client-grade PDF (ReportLab) with 5 sections —
  cover page, executive summary, findings, remediation table, recon appendix;
  machine-readable JSON output
- **NVD API Client**: Rate-limited NVD REST API v2.0 wrapper with CVSS v3.1/3.0/2.0
  parsing and keyword/product search
- **CLI**: Full `argparse` interface with `--target`, `--mode`, `--intensity`,
  `--format`, `--skip-exploit`, `--output`, `--config`, `--verbose`
- **Configuration**: `config.yaml` with deep-merge and environment variable overrides
  (`NVD_API_KEY`, `SHODAN_API_KEY`)
- **Logging**: Colour-coded console output + timestamped file logger
- **Test suite**: 15 unit and integration tests covering Config, NVDClient,
  RiskScorer, ReportGenerator, and full pipeline smoke test
- **CI/CD**: GitHub Actions workflow — test (Python 3.9/3.10/3.11), lint (flake8),
  dependency security audit (pip-audit)
- **Scripts**: `setup.sh` (one-command installer), `start_msfrpcd.sh` (MSF daemon)
- **Documentation**: `LAB_SETUP.md` (VirtualBox + Metasploitable + DVWA),
  `USAGE.md` (full command reference)

### Security Checks Implemented
- HTTP security header audit (HSTS, CSP, X-Frame-Options, etc.)
- Sensitive path probing (`.env`, `.git`, `wp-config.php`, etc.)
- Server/technology version disclosure detection
- SSH banner version disclosure + outdated version CVE matching
- FTP anonymous login test
- SMB EternalBlue (MS17-010 / CVE-2017-0144) detection
- SMB signing disabled (NTLM relay risk)
- MySQL exposed to network
- RDP BlueKeep (CVE-2019-0708) awareness
- Live NVD CVE matching for all discovered service banners

---

## [Unreleased] — Planned

### Planned
- HTML report template (Jinja2) as alternative to PDF
- Web dashboard (Flask) for live scan monitoring
- SQLite finding storage for historical comparison
- OWASP Top 10 web check module (SQLi, XSS, IDOR, XXE)
- Slack/email notification integration on scan completion
- Docker image for fully portable deployment
- Parallel multi-target scanning mode
