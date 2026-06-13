# AutoVAPT — Usage Guide

## Basic Commands

```bash
# Minimal — full scan with defaults
python3 main.py --target 192.168.56.101

# Recon only (no scanning, no exploit)
python3 main.py --target 192.168.56.101 --mode recon

# Scan only (no exploit validation)
python3 main.py --target 192.168.56.101 --mode scan

# Full pipeline, high intensity
python3 main.py --target 192.168.56.101 --mode full --intensity high

# Skip exploit validation (safer for semi-production environments)
python3 main.py --target 192.168.56.101 --skip-exploit

# JSON output only
python3 main.py --target 192.168.56.101 --format json

# Custom output directory
python3 main.py --target 192.168.56.101 --output /tmp/my_reports

# Verbose mode (debug output)
python3 main.py --target 192.168.56.101 --verbose
```

---

## Scan Intensity Profiles

| Level | Nmap Args | Speed | Noise | Use Case |
|---|---|---|---|---|
| `low` | `-sV -T2 --top-ports 100` | Slow | Minimal | IDS evasion, slow environments |
| `medium` | `-sV -sC -T3 --top-ports 1000` | Normal | Moderate | Standard assessments (default) |
| `high` | `-sV -sC -T4 -p- -A --script=vuln` | Fast | High | Full audit on lab targets |

---

## Environment Variables

| Variable | Purpose | Example |
|---|---|---|
| `NVD_API_KEY` | NVD API key for higher rate limits (50 req/30s vs 5) | `export NVD_API_KEY=abc123` |
| `SHODAN_API_KEY` | Shodan API key for external intel enrichment | `export SHODAN_API_KEY=xyz789` |

---

## Understanding the Report

### Risk Levels

| Level | Composite Score | Meaning |
|---|---|---|
| CRITICAL | ≥ 9.0 | Exploitable, severe impact — remediate immediately |
| HIGH | ≥ 7.0 | Likely exploitable, significant risk — remediate within 48 hours |
| MEDIUM | ≥ 4.0 | Possible risk vector — remediate within 30 days |
| LOW | > 0.0 | Minor risk — remediate in next maintenance window |
| INFO | 0.0 | Informational — no direct security impact |

### Composite Score Formula

```
Composite Score = min(CVSS_Base × Exploitability_Weight × Asset_Criticality, 10.0)
```

**Exploitability weights:**
- `CONFIRMED` (Metasploit validated) → ×1.2
- `POSSIBLE` (evidence-based) → ×1.0
- `NOT_EXPLOITABLE` → ×0.5
- `NO_MODULE` / `UNKNOWN` → ×0.8–0.9

**Asset criticality weights** (set in `config.yaml`):
- `critical` → ×1.3
- `high` → ×1.2
- `medium` → ×1.0 (default)
- `low` → ×0.8

---

## Output Files

```
reports/
├── autovapt_20240101_120000.pdf     ← Professional PDF (share with client/manager)
└── autovapt_20240101_120000.json    ← Raw data (SIEM/SOC ingestion)

logs/
└── autovapt_20240101_120000.log     ← Full debug log
```

---

## Metasploit RPC Setup

The exploit validation phase requires a running `msfrpcd` instance:

```bash
# Start the daemon (helper script)
./scripts/start_msfrpcd.sh

# Or manually
msfrpcd -P msf -U msf -a 127.0.0.1 -p 55553 -S -f

# Verify it's running
nc -z 127.0.0.1 55553 && echo "msfrpcd is up"
```

If `msfrpcd` is not running, AutoVAPT automatically falls back to manual validation mode (safe nmap scripts + direct connection checks).

---

## Adding Custom Vulnerability Checks

To add a new service check, edit `autovapt/modules/scanner.py`:

```python
def _check_myservice(self, ip: str, port: int, svc: dict):
    # Your check logic here
    self._add_finding({
        "title":       "My Custom Finding",
        "description": "Description of the vulnerability",
        "ip":          ip,
        "port":        port,
        "service":     "myservice",
        "severity":    "HIGH",
        "cvss_score":  7.5,
        "evidence":    "Evidence string",
        "remediation": "How to fix it",
        "cve_ids":     ["CVE-XXXX-YYYY"],
    })
```

Then register it in the `_dispatch` method:

```python
elif service == "myservice" or port == 9999:
    self._check_myservice(ip, port, svc)
```

---

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=autovapt --cov-report=term-missing

# Specific test class
pytest tests/test_autovapt.py::TestRiskScorer -v

# Specific test
pytest tests/test_autovapt.py::TestNVDClient::test_severity_from_score -v
```
