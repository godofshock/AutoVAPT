"""
AutoVAPT — Phase 1: Recon Engine
Performs host discovery, port scanning, service/version detection,
OS fingerprinting, and DNS enumeration.

Tools wrapped:
  • nmap  (via python-nmap)
  • socket / dns.resolver  (DNS enumeration fallback)
  • Shodan API  (optional — requires SHODAN_API_KEY env var)
"""

import os
import socket
import subprocess
import json
from datetime import datetime
from typing import Optional

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


# Default nmap intensity profiles
INTENSITY_PROFILES = {
    "low":    {"args": "-sV -T2 --top-ports 100 -O",         "timing": "T2"},
    "medium": {"args": "-sV -sC -T3 --top-ports 1000 -O",    "timing": "T3"},
    "high":   {"args": "-sV -sC -T4 -p- -A --script=vuln",   "timing": "T4"},
}


class ReconEngine:
    """
    Orchestrates all recon activities against the target.
    Returns a structured dict consumed by VulnerabilityScanner.
    """

    def __init__(self, target: str, config, logger):
        self.target    = target
        self.config    = config
        self.logger    = logger
        self.intensity = config.get("scan", "intensity", default="medium")
        self.nm        = nmap.PortScanner() if NMAP_AVAILABLE else None

    # ── Public ──────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """Execute all recon phases and return combined results."""
        self.logger.info(f"[+] Starting recon against: {self.target}")

        result = {
            "target":           self.target,
            "timestamp":        datetime.now().isoformat(),
            "hosts":            [],
            "open_services":    [],
            "dns_records":      {},
            "total_open_ports": 0,
            "os_guess":         {},
            "shodan_data":      {},
        }

        # 1. Nmap host/port/service scan
        if self.nm:
            nmap_data = self._run_nmap()
            result["hosts"]            = nmap_data["hosts"]
            result["open_services"]    = nmap_data["services"]
            result["total_open_ports"] = nmap_data["total_ports"]
            result["os_guess"]         = nmap_data["os_guess"]
        else:
            self.logger.warning("[!] python-nmap not found — using basic socket scan fallback")
            result["open_services"] = self._socket_scan()
            result["hosts"]         = [self.target]

        # 2. DNS enumeration
        result["dns_records"] = self._dns_enum()

        # 3. Shodan enrichment (optional)
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        if shodan_key and SHODAN_AVAILABLE:
            result["shodan_data"] = self._shodan_lookup(shodan_key)
        else:
            self.logger.debug("[*] Shodan lookup skipped (no SHODAN_API_KEY set)")

        self.logger.debug(f"[DEBUG] Recon data keys: {list(result.keys())}")
        return result

    # ── Nmap ─────────────────────────────────────────────────────────────────

    def _run_nmap(self) -> dict:
        profile = INTENSITY_PROFILES.get(self.intensity, INTENSITY_PROFILES["medium"])
        nmap_args = profile["args"]

        self.logger.info(f"[*] Running nmap: nmap {nmap_args} {self.target}")

        try:
            self.nm.scan(hosts=self.target, arguments=nmap_args)
        except Exception as e:
            self.logger.error(f"[✗] Nmap error: {e}")
            return {"hosts": [], "services": [], "total_ports": 0, "os_guess": {}}

        hosts    = []
        services = []
        os_guess = {}

        for host in self.nm.all_hosts():
            state = self.nm[host].state()
            hosts.append({"ip": host, "state": state, "hostname": self._resolve(host)})
            self.logger.info(f"    Host: {host} ({state})")

            # Ports and services
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    svc = self.nm[host][proto][port]
                    if svc["state"] == "open":
                        entry = {
                            "ip":       host,
                            "port":     port,
                            "protocol": proto,
                            "state":    svc["state"],
                            "service":  svc.get("name", ""),
                            "product":  svc.get("product", ""),
                            "version":  svc.get("version", ""),
                            "extrainfo": svc.get("extrainfo", ""),
                            "scripts":  svc.get("script", {}),
                        }
                        services.append(entry)
                        self.logger.info(
                            f"    [{port}/{proto}] {svc.get('name','')} "
                            f"{svc.get('product','')} {svc.get('version','')}"
                        )

            # OS detection
            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                best = self.nm[host]["osmatch"][0]
                os_guess[host] = {
                    "name":     best.get("name", ""),
                    "accuracy": best.get("accuracy", ""),
                }
                self.logger.info(
                    f"    OS guess: {best.get('name','')} "
                    f"(accuracy: {best.get('accuracy','')}%)"
                )

        return {
            "hosts":       hosts,
            "services":    services,
            "total_ports": len(services),
            "os_guess":    os_guess,
        }

    # ── DNS Enumeration ───────────────────────────────────────────────────────

    def _dns_enum(self) -> dict:
        """Resolve common DNS record types for the target domain."""
        # Only makes sense for domain names, not raw IPs
        target = self.target
        if self._is_ip(target):
            self.logger.debug("[*] Target is an IP — skipping DNS enum")
            return {}

        self.logger.info(f"[*] DNS enumeration for: {target}")
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        if DNS_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            for rtype in record_types:
                try:
                    answers = resolver.resolve(target, rtype)
                    records[rtype] = [str(r) for r in answers]
                    self.logger.info(f"    {rtype}: {records[rtype]}")
                except Exception:
                    pass
        else:
            # Fallback: just do A record via socket
            try:
                ip = socket.gethostbyname(target)
                records["A"] = [ip]
                self.logger.info(f"    A: {ip}")
            except Exception:
                pass

        # Basic subdomain brute (wordlist of 20 common subdomains)
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "dev", "test",
            "staging", "blog", "shop", "portal", "vpn", "git",
            "ssh", "remote", "mx", "smtp", "imap", "pop", "ns1"
        ]
        found_subs = []
        for sub in common_subs:
            fqdn = f"{sub}.{target}"
            try:
                ip = socket.gethostbyname(fqdn)
                found_subs.append({"subdomain": fqdn, "ip": ip})
                self.logger.info(f"    [subdomain] {fqdn} → {ip}")
            except socket.gaierror:
                pass

        records["subdomains"] = found_subs
        return records

    # ── Socket fallback scan ──────────────────────────────────────────────────

    def _socket_scan(self, top_ports: list = None) -> list:
        """Basic TCP connect scan as nmap fallback."""
        if top_ports is None:
            top_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389,
                5900, 8080, 8443, 8888
            ]

        self.logger.info(f"[*] Socket scan on {len(top_ports)} ports...")
        open_ports = []

        for port in top_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    open_ports.append({
                        "ip": self.target, "port": port,
                        "protocol": "tcp", "state": "open",
                        "service": self._guess_service(port),
                        "product": "", "version": "", "scripts": {}
                    })
                    self.logger.info(f"    Port {port}/tcp open")
                sock.close()
            except Exception:
                pass

        return open_ports

    # ── Shodan ────────────────────────────────────────────────────────────────

    def _shodan_lookup(self, api_key: str) -> dict:
        try:
            api  = shodan.Shodan(api_key)
            ip   = socket.gethostbyname(self.target)
            host = api.host(ip)
            self.logger.info(f"[+] Shodan: {len(host.get('data', []))} banner(s) found")
            return {
                "ip":           ip,
                "org":          host.get("org", ""),
                "country":      host.get("country_name", ""),
                "open_ports":   host.get("ports", []),
                "tags":         host.get("tags", []),
                "vulns":        list(host.get("vulns", {}).keys()),
                "last_update":  host.get("last_update", ""),
            }
        except Exception as e:
            self.logger.debug(f"[*] Shodan lookup failed: {e}")
            return {}

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            socket.inet_aton(s.split("/")[0])
            return True
        except socket.error:
            return False

    @staticmethod
    def _resolve(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    @staticmethod
    def _guess_service(port: int) -> str:
        mapping = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql",
            3389: "rdp", 5900: "vnc", 8080: "http-proxy"
        }
        return mapping.get(port, "unknown")
