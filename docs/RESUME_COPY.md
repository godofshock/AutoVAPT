# AutoVAPT — Resume & LinkedIn Copy

Use the text below exactly as written. Pick the format that matches the
section you're filling in.

---

## RESUME — Projects Section

### One-liner (for space-constrained CVs)

AutoVAPT | Python, Nmap, Metasploit RPC, NVD API, ReportLab | GitHub
- Built an end-to-end automated VAPT framework performing recon, vuln
  scanning, exploit validation, CVSS v3 risk scoring, and client-grade
  PDF reporting; confirmed EternalBlue and vsftpd backdoor on
  Metasploitable 2 with 10/10 composite risk score.

---

### Full version (recommended — 4 bullet points)

**AutoVAPT — Automated Vulnerability Assessment & Penetration Testing Framework**
*Python · Nmap · Metasploit RPC · NVD API v2.0 · ReportLab · pytest · GitHub Actions*

- Designed and built a 5-phase automated VAPT pipeline (recon → scan →
  exploit validation → risk scoring → reporting) capable of assessing
  IP ranges, domains, and CIDR blocks from a single CLI command.

- Integrated the NIST NVD REST API v2.0 to enrich all scanner findings
  with live CVE data and CVSS v3 scores at scan time; implemented
  Metasploit RPC (msfrpcd) for non-destructive check()-first exploit
  validation, confirming EternalBlue (CVE-2017-0144) and vsftpd backdoor
  (CVE-2011-2523) on Metasploitable 2.

- Engineered a composite risk scoring model (CVSS base × exploitability
  weight × asset criticality) and a ReportLab PDF report generator
  producing 5-section client-grade reports — executive summary, colour-
  coded findings, remediation priority table, and machine-readable JSON
  for SOC/SIEM ingestion.

- Achieved 15/15 unit and integration tests (pytest); shipped with GitHub
  Actions CI (test across Python 3.9–3.11, flake8 lint, pip-audit
  dependency scanning).

---

## LINKEDIN — Projects Section

**Title:** AutoVAPT — Automated VAPT Framework

**Description (paste this exactly):**

An end-to-end automated Vulnerability Assessment and Penetration Testing
framework built in Python as my M.Sc. Cybersecurity final-year capstone
project.

AutoVAPT runs a complete VAPT engagement pipeline from a single command:

Phase 1 — Recon: Nmap host/port/service/OS detection, DNS enumeration,
optional Shodan API enrichment.

Phase 2 — Vulnerability Scanner: Service-specific checks for HTTP/S,
SSH, FTP, SMB, MySQL, and RDP, enriched with live CVE data from the NIST
NVD API v2.0 at scan time.

Phase 3 — Exploit Validator: Metasploit RPC integration using check()
mode first to safely confirm exploitability; confirmed EternalBlue
(CVE-2017-0144) and FTP anonymous login on Metasploitable 2.

Phase 4 — Risk Scorer: Composite score = CVSS v3 base × exploitability
weight × asset criticality. Normalized to 0–10 scale.

Phase 5 — Report Generator: Client-grade PDF (5 sections) + JSON output
for SOC/SIEM ingestion, built with ReportLab.

Tech: Python · Nmap · Metasploit RPC · NIST NVD API · ReportLab ·
pytest (15 tests) · GitHub Actions CI

🔗 GitHub: https://github.com/YOURUSERNAME/AutoVAPT

---

## INTERVIEW — "Tell me about your major project" Answer

Keep this under 90 seconds. Practice it out loud.

"I built AutoVAPT — an automated end-to-end VAPT framework in Python.
The idea was to replicate what a junior analyst does manually across a
full engagement — recon, scanning, exploit validation, risk scoring, and
reporting — and automate all of it into one pipeline you trigger with a
single command.

The most technically interesting part was Phase 3 — exploit validation.
Instead of just reporting that a vulnerability exists, the tool connects
to the Metasploit RPC daemon and calls check() on high-severity findings
first. Check mode is non-destructive — it just confirms whether the
target is vulnerable without actually executing the payload. I used it to
confirm EternalBlue on a Metasploitable 2 VM, which gave me a confirmed
exploitable finding I could display in the report.

The risk scoring model was also something I designed from scratch. It
takes the CVSS base score, multiplies it by an exploitability weight —
so confirmed findings score higher than possible findings — and then
multiplies again by an asset criticality factor the assessor sets in the
config. The final composite score normalised to 10 determines priority
in the PDF report.

The project has 15 unit tests, GitHub Actions CI running across three
Python versions, and generates a full client-grade PDF with an executive
summary and remediation table — the kind of deliverable you'd actually
hand to a client."

---

## COVER LETTER — One paragraph to drop in

"As part of my M.Sc. Cybersecurity final year at Amity University
Rajasthan, I built AutoVAPT — an end-to-end automated VAPT framework
integrating Nmap, Metasploit RPC, and the NIST NVD API to perform
recon, vulnerability scanning, exploit validation, and risk-scored PDF
report generation from a single CLI command. The project reflects my
practical understanding of the full penetration testing lifecycle,
including CVE enrichment, composite CVSS-based risk prioritisation, and
client-ready reporting — skills I am eager to apply in a junior VAPT
analyst role."
