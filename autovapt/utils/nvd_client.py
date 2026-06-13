"""
AutoVAPT — NVD CVE Lookup Helper
Queries the NIST National Vulnerability Database API v2.0
to enrich findings with live CVE data and CVSS scores.
"""

import time
import requests
from typing import Optional


class NVDClient:
    """
    Thin wrapper around the NVD REST API v2.0.

    Free tier: ~5 requests/30 s.
    With API key (set NVD_API_KEY env var): 50 requests/30 s.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = "", timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        self._last_call = 0.0
        self._delay = 0.6 if api_key else 6.0   # respect rate limits

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def _throttle(self):
        elapsed = time.time() - self._last_call
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_call = time.time()

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        """
        Fetch full details for a specific CVE ID.
        Returns a simplified dict, or None on failure.
        """
        self._throttle()
        url = f"{self.BASE_URL}?cveId={cve_id}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            return self._parse(vulns[0]["cve"])
        except Exception:
            return None

    def search_by_keyword(self, keyword: str, max_results: int = 5) -> list:
        """
        Search CVEs by keyword (service name, product, etc.).
        Returns a list of simplified CVE dicts.
        """
        self._throttle()
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0,
        }
        try:
            resp = requests.get(
                self.BASE_URL,
                headers=self._headers(),
                params=params,
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            return [self._parse(v["cve"]) for v in data.get("vulnerabilities", [])]
        except Exception:
            return []

    def search_by_product(self, vendor: str, product: str, max_results: int = 5) -> list:
        """Search CVEs by CPE vendor/product match."""
        self._throttle()
        params = {
            "keywordSearch": f"{vendor} {product}",
            "resultsPerPage": max_results,
        }
        try:
            resp = requests.get(
                self.BASE_URL,
                headers=self._headers(),
                params=params,
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            return [self._parse(v["cve"]) for v in data.get("vulnerabilities", [])]
        except Exception:
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse(cve: dict) -> dict:
        """Flatten a CVE object into a clean dict."""
        cve_id = cve.get("id", "")
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # CVSS v3 preferred, fall back to v2
        cvss_score = 0.0
        cvss_vector = ""
        cvss_version = ""
        severity = "UNKNOWN"

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score  = m.get("baseScore", 0.0)
            cvss_vector = m.get("vectorString", "")
            cvss_version = "3.1"
            severity    = m.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score  = m.get("baseScore", 0.0)
            cvss_vector = m.get("vectorString", "")
            cvss_version = "3.0"
            severity    = m.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score  = m.get("baseScore", 0.0)
            cvss_vector = m.get("vectorString", "")
            cvss_version = "2.0"
            severity    = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

        references = [
            r.get("url", "")
            for r in cve.get("references", [])
        ]

        return {
            "cve_id":       cve_id,
            "description":  description,
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "cvss_version": cvss_version,
            "severity":     severity.upper(),
            "published":    cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "references":   references[:5],
        }

    @staticmethod
    def severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"
