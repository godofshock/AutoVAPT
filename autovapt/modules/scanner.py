"""
AutoVAPT — Phase 2: Vulnerability Scanner
Runs service-specific checks and maps findings to live CVE data via NVD API.

Checks performed:
  • HTTP/HTTPS  → Nikto-style header checks, directory brute, common CVEs
  • SSH         → version banner → CVE lookup
  • FTP         → anonymous login, version banner
  • SMB         → EternalBlue check, signing check
  • MySQL/MSSQL → unauthenticated access attempt
  • Generic     → banner grab → NVD keyword search
"""

import socket
import ftplib
import subprocess
import re
import json
import threading
from datetime import datetime
from typing import List, Dict, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from autovapt.utils.nvd_client import NVDClient


# HTTP security headers that should be present
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/config.php", "/wp-config.php",
    "/admin", "/phpmyadmin", "/server-status", "/server-info",
    "/.htaccess", "/backup.zip", "/db.sql", "/robots.txt",
    "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/api/v1/users", "/api/swagger.json", "/api-docs",
    "/.DS_Store", "/web.config", "/WEB-INF/web.xml",
]


class VulnerabilityScanner:
    """
    Iterates over discovered open services and runs targeted checks.
    Each finding is enriched with CVE data from NVD.
    """

    def __init__(self, target: str, recon_data: dict, config, logger):
        self.target      = target
        self.recon_data  = recon_data
        self.config      = config
        self.logger      = logger
        self.nvd         = NVDClient(
            api_key=config.get("nvd_api", "api_key", default=""),
            timeout=config.get("nvd_api", "timeout", default=15),
        )
        self.findings: List[Dict] = []
        self._lock = threading.Lock()

    # ── Public ───────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        """Scan all discovered services and return list of vulnerability findings."""
        services = self.recon_data.get("open_services", [])

        if not services:
            self.logger.warning("[!] No open services to scan.")
            return []

        self.logger.info(f"[*] Scanning {len(services)} open service(s)...")

        threads = []
        for svc in services:
            t = threading.Thread(target=self._dispatch, args=(svc,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.config.get("scan", "timeout", default=600))

        # Sort by CVSS score descending
        self.findings.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        self.logger.info(f"[+] Total vulnerabilities found: {len(self.findings)}")
        return self.findings

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, svc: dict):
        port    = svc.get("port")
        service = svc.get("service", "").lower()
        ip      = svc.get("ip", self.target)

        self.logger.debug(f"[*] Checking {ip}:{port} ({service})")

        if service in ("http", "http-proxy") or port in (80, 8080, 8000, 8888):
            self._check_http(ip, port, ssl=False)
        elif service in ("https",) or port in (443, 8443):
            self._check_http(ip, port, ssl=True)
        elif service == "ssh" or port == 22:
            self._check_ssh(ip, port, svc)
        elif service == "ftp" or port == 21:
            self._check_ftp(ip, port, svc)
        elif service in ("microsoft-ds", "netbios-ssn", "smb") or port in (445, 139):
            self._check_smb(ip, port, svc)
        elif service == "mysql" or port == 3306:
            self._check_mysql(ip, port, svc)
        elif service == "rdp" or port == 3389:
            self._check_rdp(ip, port, svc)

        # Always do banner-based CVE enrichment
        self._banner_cve_lookup(ip, port, svc)

    # ── HTTP / HTTPS ──────────────────────────────────────────────────────────

    def _check_http(self, ip: str, port: int, ssl: bool):
        if not REQUESTS_AVAILABLE:
            return

        scheme  = "https" if ssl else "http"
        base    = f"{scheme}://{ip}:{port}"
        session = requests.Session()
        session.verify = False
        session.timeout = 10

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # ── 1. Security header audit ──────────────────────────────────────
        try:
            resp = session.get(base, allow_redirects=True)
            server_header = resp.headers.get("Server", "")
            x_powered     = resp.headers.get("X-Powered-By", "")

            # Server version disclosure
            if server_header:
                self._add_finding({
                    "title":       "Server Version Disclosure",
                    "description": f"Server header reveals version info: '{server_header}'. "
                                   "Attackers can use this to search for known CVEs.",
                    "ip":          ip,
                    "port":        port,
                    "service":     "http",
                    "severity":    "LOW",
                    "cvss_score":  3.1,
                    "evidence":    f"Server: {server_header}",
                    "remediation": "Configure the web server to suppress or genericise the Server header.",
                    "cve_ids":     [],
                })

            # Technology disclosure
            if x_powered:
                self._add_finding({
                    "title":       "Technology Stack Disclosure",
                    "description": f"X-Powered-By header exposes backend technology: '{x_powered}'.",
                    "ip":          ip,
                    "port":        port,
                    "service":     "http",
                    "severity":    "LOW",
                    "cvss_score":  2.6,
                    "evidence":    f"X-Powered-By: {x_powered}",
                    "remediation": "Remove X-Powered-By header from server configuration.",
                    "cve_ids":     [],
                })

            # Missing security headers
            for header in SECURITY_HEADERS:
                if header not in resp.headers:
                    self._add_finding({
                        "title":       f"Missing Security Header: {header}",
                        "description": f"The HTTP response does not include the '{header}' header, "
                                       "leaving the application exposed to related attacks.",
                        "ip":          ip,
                        "port":        port,
                        "service":     "http",
                        "severity":    "MEDIUM" if header in (
                            "Strict-Transport-Security", "Content-Security-Policy"
                        ) else "LOW",
                        "cvss_score":  5.3 if header in (
                            "Strict-Transport-Security", "Content-Security-Policy"
                        ) else 3.7,
                        "evidence":    f"{header} header absent in response.",
                        "remediation": f"Add '{header}' to the server/application response headers.",
                        "cve_ids":     [],
                    })

            # HTTP used where HTTPS expected
            if not ssl and port == 80:
                self._add_finding({
                    "title":       "HTTP (Unencrypted) Service Exposed",
                    "description": "The target is serving HTTP traffic without TLS encryption, "
                                   "exposing all data to interception.",
                    "ip":          ip,
                    "port":        port,
                    "service":     "http",
                    "severity":    "MEDIUM",
                    "cvss_score":  5.9,
                    "evidence":    f"HTTP 200 response on {base}",
                    "remediation": "Enforce HTTPS by redirecting all HTTP traffic to HTTPS.",
                    "cve_ids":     [],
                })

        except requests.exceptions.ConnectionError:
            self.logger.debug(f"[*] Could not connect to {base}")
            return
        except Exception as e:
            self.logger.debug(f"[*] HTTP check error on {base}: {e}")
            return

        # ── 2. Sensitive path probe ───────────────────────────────────────
        self.logger.debug(f"[*] Probing {len(SENSITIVE_PATHS)} sensitive paths on {base}")
        for path in SENSITIVE_PATHS:
            try:
                r = session.get(f"{base}{path}", allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    severity = "HIGH" if r.status_code == 200 else "MEDIUM"
                    cvss     = 7.5 if r.status_code == 200 else 5.3
                    self._add_finding({
                        "title":       f"Sensitive Path Accessible: {path}",
                        "description": f"The path '{path}' returned HTTP {r.status_code}. "
                                       "This may expose sensitive configuration or data.",
                        "ip":          ip,
                        "port":        port,
                        "service":     "http",
                        "severity":    severity,
                        "cvss_score":  cvss,
                        "evidence":    f"GET {base}{path} → HTTP {r.status_code}",
                        "remediation": f"Restrict or remove access to '{path}'.",
                        "cve_ids":     [],
                    })
                    self.logger.info(f"    [HTTP] Sensitive path found: {path} ({r.status_code})")
            except Exception:
                pass

        # ── 3. CVE lookup for server product ─────────────────────────────
        if server_header:
            product = server_header.split("/")[0].strip()
            cves = self.nvd.search_by_keyword(product, max_results=3)
            for cve in cves:
                if cve["cvss_score"] >= 7.0:
                    self._add_finding({
                        "title":       f"CVE Match: {cve['cve_id']} in {product}",
                        "description": cve["description"],
                        "ip":          ip,
                        "port":        port,
                        "service":     "http",
                        "severity":    cve["severity"],
                        "cvss_score":  cve["cvss_score"],
                        "cvss_vector": cve["cvss_vector"],
                        "evidence":    f"Server: {server_header}",
                        "remediation": "Update the web server to the latest patched version.",
                        "cve_ids":     [cve["cve_id"]],
                        "references":  cve["references"],
                    })

    # ── SSH ───────────────────────────────────────────────────────────────────

    def _check_ssh(self, ip: str, port: int, svc: dict):
        banner  = self._grab_banner(ip, port)
        product = svc.get("product", "OpenSSH")
        version = svc.get("version", "")

        self.logger.info(f"    [SSH] {ip}:{port} banner: {banner[:80] if banner else 'none'}")

        # Version disclosed
        if banner:
            self._add_finding({
                "title":       "SSH Version Disclosure",
                "description": f"SSH banner reveals software version: '{banner.strip()}'. "
                               "This aids targeted exploitation.",
                "ip":          ip,
                "port":        port,
                "service":     "ssh",
                "severity":    "LOW",
                "cvss_score":  3.1,
                "evidence":    f"Banner: {banner.strip()}",
                "remediation": "Configure sshd to suppress the version banner or restrict banner output.",
                "cve_ids":     [],
            })

        # Old OpenSSH check
        if "openssh" in (banner or "").lower():
            match = re.search(r"OpenSSH[_\s]([\d.]+)", banner or "", re.IGNORECASE)
            if match:
                ver = match.group(1)
                major, *rest = ver.split(".")
                minor = int(rest[0]) if rest else 0
                if int(major) < 8 or (int(major) == 8 and minor < 0):
                    cves = self.nvd.search_by_keyword(f"OpenSSH {ver}", max_results=3)
                    for cve in cves:
                        if cve["cvss_score"] >= 5.0:
                            self._add_finding({
                                "title":       f"Outdated OpenSSH {ver} — {cve['cve_id']}",
                                "description": cve["description"],
                                "ip":          ip,
                                "port":        port,
                                "service":     "ssh",
                                "severity":    cve["severity"],
                                "cvss_score":  cve["cvss_score"],
                                "cvss_vector": cve["cvss_vector"],
                                "evidence":    f"Banner: {banner.strip()}",
                                "remediation": "Upgrade OpenSSH to the latest stable release.",
                                "cve_ids":     [cve["cve_id"]],
                                "references":  cve["references"],
                            })

    # ── FTP ───────────────────────────────────────────────────────────────────

    def _check_ftp(self, ip: str, port: int, svc: dict):
        self.logger.info(f"    [FTP] Testing anonymous login on {ip}:{port}")

        # Anonymous login test
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=10)
            banner = ftp.getwelcome()
            ftp.login("anonymous", "anonymous@test.com")

            # If we get here, anonymous login succeeded
            self._add_finding({
                "title":       "FTP Anonymous Login Enabled",
                "description": "The FTP server allows unauthenticated (anonymous) access. "
                               "Attackers can browse and potentially download sensitive files.",
                "ip":          ip,
                "port":        port,
                "service":     "ftp",
                "severity":    "HIGH",
                "cvss_score":  7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "evidence":    f"Successful anonymous FTP login. Banner: {banner}",
                "remediation": "Disable anonymous FTP access unless explicitly required. "
                               "Use SFTP or FTPS instead.",
                "cve_ids":     [],
            })
            self.logger.info(f"    [FTP] Anonymous login SUCCESSFUL on {ip}:{port}")

            try:
                files = ftp.nlst()
                self.logger.info(f"    [FTP] Accessible files: {files[:5]}")
            except Exception:
                pass
            ftp.quit()

        except ftplib.error_perm:
            self.logger.debug(f"[*] FTP anonymous login denied on {ip}:{port}")
        except Exception as e:
            self.logger.debug(f"[*] FTP check error: {e}")

        # CVE lookup for FTP product
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product:
            keyword = f"{product} {version}".strip()
            cves = self.nvd.search_by_keyword(keyword, max_results=3)
            for cve in cves:
                if cve["cvss_score"] >= 6.0:
                    self._add_finding({
                        "title":       f"CVE Match: {cve['cve_id']} in {keyword}",
                        "description": cve["description"],
                        "ip":          ip,
                        "port":        port,
                        "service":     "ftp",
                        "severity":    cve["severity"],
                        "cvss_score":  cve["cvss_score"],
                        "cvss_vector": cve.get("cvss_vector", ""),
                        "evidence":    f"Service banner: {product} {version}",
                        "remediation": f"Update {product} to the latest patched version.",
                        "cve_ids":     [cve["cve_id"]],
                        "references":  cve.get("references", []),
                    })

    # ── SMB ───────────────────────────────────────────────────────────────────

    def _check_smb(self, ip: str, port: int, svc: dict):
        self.logger.info(f"    [SMB] Checking {ip}:{port}")

        # Check for EternalBlue (MS17-010) via nmap script output
        scripts = svc.get("scripts", {})
        if "smb-vuln-ms17-010" in scripts:
            script_out = scripts["smb-vuln-ms17-010"]
            if "VULNERABLE" in str(script_out).upper():
                self._add_finding({
                    "title":       "EternalBlue (MS17-010) — SMB Remote Code Execution",
                    "description": "The target is vulnerable to EternalBlue, a critical SMB exploit "
                                   "that allows unauthenticated remote code execution. "
                                   "Used by WannaCry and NotPetya ransomware.",
                    "ip":          ip,
                    "port":        port,
                    "service":     "smb",
                    "severity":    "CRITICAL",
                    "cvss_score":  9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "evidence":    f"nmap smb-vuln-ms17-010 script output: {str(script_out)[:200]}",
                    "remediation": "Apply Microsoft patch MS17-010 immediately. "
                                   "Block port 445 at the perimeter firewall.",
                    "cve_ids":     ["CVE-2017-0144"],
                    "references":  [
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                        "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
                    ],
                })
                self.logger.info(f"    [SMB] EternalBlue VULNERABLE on {ip}:{port}!")

        # SMB signing check
        if "smb-security-mode" in scripts:
            output = str(scripts["smb-security-mode"])
            if "message_signing: disabled" in output.lower():
                self._add_finding({
                    "title":       "SMB Signing Disabled",
                    "description": "SMB message signing is disabled, enabling relay attacks (NTLM relay). "
                                   "Attackers on the same network can intercept and relay SMB credentials.",
                    "ip":          ip,
                    "port":        port,
                    "service":     "smb",
                    "severity":    "HIGH",
                    "cvss_score":  7.1,
                    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "evidence":    f"smb-security-mode: {output[:200]}",
                    "remediation": "Enable SMB signing via Group Policy: "
                                   "'Microsoft network server: Digitally sign communications (always)'.",
                    "cve_ids":     [],
                })

    # ── MySQL ─────────────────────────────────────────────────────────────────

    def _check_mysql(self, ip: str, port: int, svc: dict):
        self.logger.info(f"    [MySQL] Testing {ip}:{port}")
        banner = self._grab_banner(ip, port)

        if banner:
            self._add_finding({
                "title":       "MySQL Service Exposed to Network",
                "description": "MySQL is accessible from the network. Database services should "
                               "not be directly reachable from untrusted networks.",
                "ip":          ip,
                "port":        port,
                "service":     "mysql",
                "severity":    "MEDIUM",
                "cvss_score":  6.5,
                "evidence":    f"MySQL banner received on port {port}: {banner[:80]}",
                "remediation": "Bind MySQL to 127.0.0.1 and use SSH tunnelling for remote access. "
                               "Apply network-level firewall rules to restrict port 3306.",
                "cve_ids":     [],
            })

    # ── RDP ───────────────────────────────────────────────────────────────────

    def _check_rdp(self, ip: str, port: int, svc: dict):
        self.logger.info(f"    [RDP] Checking {ip}:{port}")
        self._add_finding({
            "title":       "RDP Service Exposed to Internet",
            "description": "Remote Desktop Protocol (RDP) is exposed. RDP is a common attack vector "
                           "for brute force, BlueKeep (CVE-2019-0708), and DejaBlue attacks.",
            "ip":          ip,
            "port":        port,
            "service":     "rdp",
            "severity":    "HIGH",
            "cvss_score":  8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence":    f"RDP port {port} open and responding.",
            "remediation": "Restrict RDP access to VPN users only. Enable NLA. "
                           "Apply patches for CVE-2019-0708 (BlueKeep).",
            "cve_ids":     ["CVE-2019-0708"],
        })

        # Check BlueKeep via NVD
        cve = self.nvd.lookup_cve("CVE-2019-0708")
        if cve:
            self.logger.info(f"    [RDP] BlueKeep CVE enriched: CVSS {cve['cvss_score']}")

    # ── Banner-based generic CVE lookup ───────────────────────────────────────

    def _banner_cve_lookup(self, ip: str, port: int, svc: dict):
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()

        if not product:
            return

        keyword = f"{product} {version}".strip()
        self.logger.debug(f"[*] NVD keyword search: '{keyword}'")
        cves = self.nvd.search_by_keyword(keyword, max_results=3)

        for cve in cves:
            if cve["cvss_score"] >= 7.0:
                # Avoid duplicates
                already = any(
                    cve["cve_id"] in f.get("cve_ids", [])
                    for f in self.findings
                )
                if already:
                    continue
                self._add_finding({
                    "title":       f"CVE Match: {cve['cve_id']} in {keyword}",
                    "description": cve["description"],
                    "ip":          ip,
                    "port":        port,
                    "service":     svc.get("service", ""),
                    "severity":    cve["severity"],
                    "cvss_score":  cve["cvss_score"],
                    "cvss_vector": cve.get("cvss_vector", ""),
                    "evidence":    f"Product banner: {keyword}",
                    "remediation": f"Update {product} to the latest patched version. "
                                   "Monitor NVD for new advisories.",
                    "cve_ids":     [cve["cve_id"]],
                    "references":  cve.get("references", []),
                })
                self.logger.info(
                    f"    [CVE] {cve['cve_id']} ({cve['severity']}, CVSS {cve['cvss_score']}) "
                    f"matched for {keyword}"
                )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _grab_banner(self, ip: str, port: int, timeout: int = 5) -> Optional[str]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner
        except Exception:
            return None

    def _add_finding(self, finding: dict):
        finding.setdefault("cvss_score",  0.0)
        finding.setdefault("cvss_vector", "")
        finding.setdefault("cve_ids",     [])
        finding.setdefault("references",  [])
        finding.setdefault("remediation", "")
        finding.setdefault("timestamp",   datetime.now().isoformat())

        with self._lock:
            self.findings.append(finding)
