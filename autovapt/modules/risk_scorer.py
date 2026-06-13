"""
AutoVAPT — Phase 4: Risk Scorer
Computes a composite risk score for each vulnerability using:

  Composite Score = CVSS Base Score
                  × Exploitability Multiplier   (was it confirmed exploitable?)
                  × Asset Criticality Multiplier (how important is the target asset?)

Final scores are normalised to 0–10 and mapped to a risk level:
  CRITICAL ≥ 9.0 | HIGH ≥ 7.0 | MEDIUM ≥ 4.0 | LOW > 0 | INFO = 0
"""

from datetime import datetime
from typing import List, Dict

# Multipliers
EXPLOITABILITY_WEIGHT = {
    "CONFIRMED":       1.2,
    "POSSIBLE":        1.0,
    "NOT_EXPLOITABLE": 0.5,
    "NO_MODULE":       0.9,
    "ERROR":           0.8,
    "UNKNOWN":         0.8,
}

ASSET_CRITICALITY_WEIGHT = {
    "critical": 1.3,
    "high":     1.2,
    "medium":   1.0,
    "low":      0.8,
}

SEVERITY_LABEL = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFO",
}


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


class RiskScorer:
    """
    Combines scanner findings with exploit validation results to produce
    a prioritised, scored list of risks.
    """

    def __init__(self, findings: List[Dict], exploits: List[Dict], config, logger):
        self.findings    = findings
        self.exploits    = exploits
        self.config      = config
        self.logger      = logger
        self.scored: List[Dict] = []

        # Build a quick lookup: title+port → exploit status
        self._exploit_map: Dict[str, str] = {}
        for e in exploits:
            key = f"{e.get('finding_title','')}:{e.get('port','')}"
            self._exploit_map[key] = e.get("status", "UNKNOWN")

    # ── Public ───────────────────────────────────────────────────────────────

    def run(self) -> List[Dict]:
        """Score all findings and return sorted list."""
        asset_key = self.config.get("risk", "asset_criticality", default="medium").lower()
        asset_mult = ASSET_CRITICALITY_WEIGHT.get(asset_key, 1.0)

        self.logger.info(f"[*] Asset criticality: {asset_key} (×{asset_mult})")

        for finding in self.findings:
            scored = self._score(finding, asset_mult)
            self.scored.append(scored)

        # Sort: composite score descending
        self.scored.sort(key=lambda x: x["composite_score"], reverse=True)
        return self.scored

    def get_summary(self) -> Dict:
        """Return high-level summary statistics for the report."""
        if not self.scored:
            return {
                "total":        0,
                "critical":     0,
                "high":         0,
                "medium":       0,
                "low":          0,
                "info":         0,
                "overall_risk": "NONE",
                "timestamp":    datetime.now().isoformat(),
            }

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for s in self.scored:
            lvl = s.get("risk_level", "INFO")
            counts[lvl] = counts.get(lvl, 0) + 1

        if counts["CRITICAL"] > 0:
            overall = "CRITICAL"
        elif counts["HIGH"] >= 3:
            overall = "CRITICAL"
        elif counts["HIGH"] > 0:
            overall = "HIGH"
        elif counts["MEDIUM"] > 0:
            overall = "MEDIUM"
        else:
            overall = "LOW"

        top3 = [
            {
                "title":           s["title"],
                "composite_score": s["composite_score"],
                "risk_level":      s["risk_level"],
                "cve_ids":         s.get("cve_ids", []),
            }
            for s in self.scored[:3]
        ]

        return {
            "total":         len(self.scored),
            "critical":      counts["CRITICAL"],
            "high":          counts["HIGH"],
            "medium":        counts["MEDIUM"],
            "low":           counts["LOW"],
            "info":          counts["INFO"],
            "overall_risk":  overall,
            "top_findings":  top3,
            "timestamp":     datetime.now().isoformat(),
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _score(self, finding: dict, asset_mult: float) -> dict:
        title     = finding.get("title", "")
        port      = finding.get("port", "")
        base_cvss = float(finding.get("cvss_score", 0))

        # Look up exploit status for this finding
        key          = f"{title}:{port}"
        exploit_stat = self._exploit_map.get(key, "UNKNOWN")
        exp_mult     = EXPLOITABILITY_WEIGHT.get(exploit_stat, 0.8)

        # Composite score (capped at 10.0)
        composite = min(base_cvss * exp_mult * asset_mult, 10.0)
        composite = round(composite, 2)

        risk_level = score_to_severity(composite)

        scored_finding = dict(finding)
        scored_finding.update({
            "composite_score":         composite,
            "risk_level":              risk_level,
            "exploit_status":          exploit_stat,
            "exploitability_weight":   exp_mult,
            "asset_criticality_weight": asset_mult,
            "scored_at":               datetime.now().isoformat(),
        })

        self.logger.debug(
            f"[SCORE] {title[:50]:<50} "
            f"CVSS={base_cvss} × exp={exp_mult} × asset={asset_mult} "
            f"= {composite} ({risk_level})"
        )

        return scored_finding
