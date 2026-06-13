"""
AutoVAPT Test Suite
Run with: pytest tests/ -v --cov=autovapt
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from autovapt.utils.config import Config
from autovapt.utils.nvd_client import NVDClient
from autovapt.modules.risk_scorer import RiskScorer, score_to_severity
from autovapt.modules.report_generator import ReportGenerator


# ── Config tests ─────────────────────────────────────────────────────────────

class TestConfig:

    def test_defaults_loaded(self):
        cfg = Config("nonexistent_file.yaml")
        assert cfg.get("nmap", "timing") == "T3"
        assert cfg.get("risk", "asset_criticality") == "medium"

    def test_default_fallback(self):
        cfg = Config("nonexistent_file.yaml")
        assert cfg.get("nonexistent", "key", default="fallback") == "fallback"

    def test_env_var_nvd_key(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "testkey123")
        cfg = Config("nonexistent_file.yaml")
        assert cfg.get("nvd_api", "api_key") == "testkey123"

    def test_nested_get(self):
        cfg = Config("nonexistent_file.yaml")
        assert isinstance(cfg.get("nmap", "top_ports"), int)
        assert cfg.get("nmap", "top_ports") == 1000


# ── NVD Client tests ──────────────────────────────────────────────────────────

class TestNVDClient:

    def test_severity_from_score(self):
        client = NVDClient()
        assert client.severity_from_score(9.5)  == "CRITICAL"
        assert client.severity_from_score(8.0)  == "HIGH"
        assert client.severity_from_score(5.0)  == "MEDIUM"
        assert client.severity_from_score(2.0)  == "LOW"
        assert client.severity_from_score(0.0)  == "INFO"

    def test_parse_minimal_cve(self):
        """Ensure _parse handles a minimal CVE object without crashing."""
        minimal = {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
            "metrics": {},
            "references": [],
        }
        result = NVDClient._parse(minimal)
        assert result["cve_id"]    == "CVE-2024-0001"
        assert result["severity"]  == "UNKNOWN"
        assert result["cvss_score"] == 0.0

    def test_throttle_respects_delay(self):
        import time
        client = NVDClient(api_key="", timeout=5)
        client._delay = 0.1
        start = time.time()
        client._throttle()
        client._throttle()
        elapsed = time.time() - start
        assert elapsed >= 0.05  # at least some delay applied


# ── Risk Scorer tests ─────────────────────────────────────────────────────────

class TestRiskScorer:

    def _make_config(self):
        cfg = Config("nonexistent_file.yaml")
        return cfg

    def test_score_to_severity(self):
        assert score_to_severity(9.5) == "CRITICAL"
        assert score_to_severity(9.0) == "CRITICAL"
        assert score_to_severity(7.5) == "HIGH"
        assert score_to_severity(7.0) == "HIGH"
        assert score_to_severity(5.0) == "MEDIUM"
        assert score_to_severity(4.0) == "MEDIUM"
        assert score_to_severity(2.0) == "LOW"
        assert score_to_severity(0.0) == "INFO"

    def test_basic_scoring(self):
        findings = [
            {"title": "Test Vuln", "cvss_score": 8.0, "severity": "HIGH",
             "ip": "10.0.0.1", "port": 80, "service": "http",
             "cve_ids": [], "description": "desc", "evidence": "ev",
             "remediation": "fix"},
        ]
        cfg = self._make_config()
        import logging
        logger = logging.getLogger("test")
        scorer = RiskScorer(findings, [], cfg, logger)
        results = scorer.run()
        assert len(results) == 1
        assert results[0]["composite_score"] > 0
        assert results[0]["risk_level"] in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")

    def test_exploit_multiplier_confirmed(self):
        """Confirmed exploit should increase composite score."""
        findings = [
            {"title": "SMB RCE", "cvss_score": 9.8, "severity": "CRITICAL",
             "ip": "10.0.0.1", "port": 445, "service": "smb",
             "cve_ids": ["CVE-2017-0144"], "description": "", "evidence": "", "remediation": ""},
        ]
        exploits_confirmed = [
            {"finding_title": "SMB RCE", "port": 445, "status": "CONFIRMED"}
        ]
        exploits_none = []

        import logging
        logger = logging.getLogger("test")
        cfg = self._make_config()

        scorer_c = RiskScorer(findings, exploits_confirmed, cfg, logger)
        scorer_n = RiskScorer(findings, exploits_none, cfg, logger)

        res_c = scorer_c.run()[0]["composite_score"]
        res_n = scorer_n.run()[0]["composite_score"]

        # Confirmed should be >= unknown (capped at 10)
        assert res_c >= res_n or res_c == 10.0

    def test_summary_overall_risk(self):
        import logging
        logger = logging.getLogger("test")
        cfg = self._make_config()

        # No findings → NONE
        scorer = RiskScorer([], [], cfg, logger)
        scorer.run()
        assert scorer.get_summary()["overall_risk"] == "NONE"

    def test_summary_counts(self):
        import logging
        logger = logging.getLogger("test")
        cfg = self._make_config()

        findings = [
            {"title": f"Vuln {i}", "cvss_score": score, "severity": sev,
             "ip": "10.0.0.1", "port": 80, "service": "http",
             "cve_ids": [], "description": "", "evidence": "", "remediation": ""}
            for i, (score, sev) in enumerate([
                (9.5, "CRITICAL"), (8.0, "HIGH"), (5.0, "MEDIUM"), (2.0, "LOW")
            ])
        ]
        scorer = RiskScorer(findings, [], cfg, logger)
        scorer.run()
        summary = scorer.get_summary()
        assert summary["total"] == 4
        # With default medium asset weight (×1.0) and UNKNOWN exploit weight (×0.8):
        # 9.5 × 0.8 × 1.0 = 7.6 → HIGH; 8.0 × 0.8 = 6.4 → MEDIUM
        # So at least 1 finding should be HIGH or CRITICAL
        assert summary["critical"] + summary["high"] >= 1


# ── Report Generator tests ────────────────────────────────────────────────────

class TestReportGenerator:

    def _sample_results(self):
        return {
            "scan_id":    "20240101_120000",
            "target":     "192.168.1.10",
            "mode":       "full",
            "timestamp":  "2024-01-01T12:00:00",
            "recon":      {"hosts": [{"ip": "192.168.1.10", "state": "up"}],
                           "open_services": [], "total_open_ports": 0,
                           "dns_records": {}, "os_guess": {}},
            "vulnerabilities": [],
            "exploits":   [],
            "risk_scores": [],
            "summary":    {
                "total": 0, "critical": 0, "high": 0,
                "medium": 0, "low": 0, "info": 0,
                "overall_risk": "NONE", "top_findings": [],
            },
        }

    def test_json_generation(self, tmp_path):
        import logging
        logger = logging.getLogger("test")
        gen = ReportGenerator(self._sample_results(), str(tmp_path), "test_001", logger)
        path = gen.generate_json()
        assert os.path.exists(path)
        import json
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "192.168.1.10"

    def test_text_fallback(self, tmp_path):
        import logging
        logger = logging.getLogger("test")
        gen = ReportGenerator(self._sample_results(), str(tmp_path), "test_001", logger)
        txt_path = str(tmp_path / "fallback.txt")
        gen._write_text_fallback(txt_path)
        assert os.path.exists(txt_path)
        with open(txt_path) as f:
            content = f.read()
        assert "AutoVAPT" in content
        assert "192.168.1.10" in content


# ── Integration smoke test ────────────────────────────────────────────────────

class TestIntegration:
    """
    Smoke test: run the full pipeline against a mock recon result
    without real network calls.
    """

    def test_pipeline_no_services(self, tmp_path):
        """Pipeline should complete gracefully with zero findings."""
        import logging
        logger = logging.getLogger("test")
        cfg = Config("nonexistent_file.yaml")

        mock_recon = {
            "target": "127.0.0.1",
            "timestamp": "2024-01-01T00:00:00",
            "hosts": [{"ip": "127.0.0.1", "state": "up"}],
            "open_services": [],
            "total_open_ports": 0,
            "dns_records": {},
            "os_guess": {},
        }

        from autovapt.modules.scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner("127.0.0.1", mock_recon, cfg, logger)
        findings = scanner.run()
        assert isinstance(findings, list)

        from autovapt.modules.risk_scorer import RiskScorer
        scorer = RiskScorer(findings, [], cfg, logger)
        scored = scorer.run()
        assert isinstance(scored, list)

        summary = scorer.get_summary()
        assert summary["total"] == 0
        assert summary["overall_risk"] == "NONE"

        from autovapt.modules.report_generator import ReportGenerator
        results = {
            "scan_id": "smoke_001", "target": "127.0.0.1", "mode": "full",
            "timestamp": "2024-01-01T00:00:00",
            "recon": mock_recon, "vulnerabilities": findings,
            "exploits": [], "risk_scores": scored, "summary": summary,
        }
        gen  = ReportGenerator(results, str(tmp_path), "smoke_001", logger)
        path = gen.generate_json()
        assert os.path.exists(path)
