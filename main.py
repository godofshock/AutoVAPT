#!/usr/bin/env python3
"""
AutoVAPT - Main Entry Point
Usage: python main.py --target <IP/domain> [options]
"""

import argparse
import sys
import os
import json
from datetime import datetime

from autovapt.modules.recon import ReconEngine
from autovapt.modules.scanner import VulnerabilityScanner
from autovapt.modules.exploit_validator import ExploitValidator
from autovapt.modules.risk_scorer import RiskScorer
from autovapt.modules.report_generator import ReportGenerator
from autovapt.utils.logger import setup_logger
from autovapt.utils.config import Config
from autovapt.utils.banner import print_banner


def parse_args():
    parser = argparse.ArgumentParser(
        prog="AutoVAPT",
        description="Automated Vulnerability Assessment & Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 192.168.1.10
  python main.py --target example.com --mode full
  python main.py --target 192.168.1.0/24 --mode recon --output /tmp/reports
  python main.py --target 10.0.0.5 --skip-exploit --format json
        """
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP, domain, or CIDR range (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["recon", "scan", "full"],
        default="full",
        help="Assessment mode: recon-only, scan-only, or full pipeline (default: full)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["pdf", "json", "both"],
        default="both",
        help="Report output format (default: both)"
    )
    parser.add_argument(
        "--skip-exploit",
        action="store_true",
        help="Skip exploit validation phase (safer for production environments)"
    )
    parser.add_argument(
        "--intensity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Scan intensity level (default: medium)"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="AutoVAPT v1.0.0"
    )

    return parser.parse_args()


def run_pipeline(args, logger, config):
    """Execute the full VAPT pipeline."""
    
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = args.target
    
    logger.info(f"[*] Scan ID     : {scan_id}")
    logger.info(f"[*] Target      : {target}")
    logger.info(f"[*] Mode        : {args.mode}")
    logger.info(f"[*] Intensity   : {args.intensity}")
    logger.info(f"[*] Output Dir  : {args.output}")
    logger.info(f"[*] Skip Exploit: {args.skip_exploit}")
    logger.info("")

    results = {
        "scan_id": scan_id,
        "target": target,
        "mode": args.mode,
        "intensity": args.intensity,
        "timestamp": datetime.now().isoformat(),
        "recon": {},
        "vulnerabilities": [],
        "exploits": [],
        "risk_scores": [],
        "summary": {}
    }

    # ─── PHASE 1: RECON ──────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  PHASE 1 — RECONNAISSANCE")
    logger.info("=" * 60)

    recon = ReconEngine(target, config, logger)
    recon_data = recon.run()
    results["recon"] = recon_data

    logger.info(f"[+] Recon complete. Hosts discovered: {len(recon_data.get('hosts', []))}")
    logger.info(f"[+] Open ports found: {recon_data.get('total_open_ports', 0)}")

    if args.mode == "recon":
        logger.info("[*] Recon-only mode selected. Skipping scan and exploit phases.")
        _finalize(results, args, scan_id, logger)
        return results

    # ─── PHASE 2: VULNERABILITY SCAN ─────────────────────────────────────────
    logger.info("")
    logger.info("=" * 60)
    logger.info("  PHASE 2 — VULNERABILITY SCANNING")
    logger.info("=" * 60)

    scanner = VulnerabilityScanner(target, recon_data, config, logger)
    vuln_data = scanner.run()
    results["vulnerabilities"] = vuln_data

    logger.info(f"[+] Scan complete. Vulnerabilities found: {len(vuln_data)}")
    critical = [v for v in vuln_data if v.get("severity") == "CRITICAL"]
    high = [v for v in vuln_data if v.get("severity") == "HIGH"]
    logger.info(f"    Critical: {len(critical)} | High: {len(high)}")

    if args.mode == "scan":
        logger.info("[*] Scan-only mode selected. Skipping exploit phase.")
        _finalize(results, args, scan_id, logger)
        return results

    # ─── PHASE 3: EXPLOIT VALIDATION ─────────────────────────────────────────
    logger.info("")
    logger.info("=" * 60)
    logger.info("  PHASE 3 — EXPLOIT VALIDATION")
    logger.info("=" * 60)

    if args.skip_exploit:
        logger.warning("[!] Exploit validation skipped (--skip-exploit flag set)")
        results["exploits"] = []
    else:
        validator = ExploitValidator(target, vuln_data, config, logger)
        exploit_data = validator.run()
        results["exploits"] = exploit_data
        confirmed = [e for e in exploit_data if e.get("status") == "CONFIRMED"]
        logger.info(f"[+] Exploits attempted: {len(exploit_data)}")
        logger.info(f"[+] Confirmed exploitable: {len(confirmed)}")

    # ─── PHASE 4: RISK SCORING ────────────────────────────────────────────────
    logger.info("")
    logger.info("=" * 60)
    logger.info("  PHASE 4 — RISK SCORING")
    logger.info("=" * 60)

    scorer = RiskScorer(results["vulnerabilities"], results["exploits"], config, logger)
    risk_data = scorer.run()
    results["risk_scores"] = risk_data
    results["summary"] = scorer.get_summary()

    logger.info(f"[+] Risk scoring complete.")
    logger.info(f"    Overall risk level: {results['summary'].get('overall_risk', 'UNKNOWN')}")

    # ─── PHASE 5: REPORT GENERATION ──────────────────────────────────────────
    logger.info("")
    logger.info("=" * 60)
    logger.info("  PHASE 5 — REPORT GENERATION")
    logger.info("=" * 60)

    _finalize(results, args, scan_id, logger)
    return results


def _finalize(results, args, scan_id, logger):
    """Generate final reports."""
    os.makedirs(args.output, exist_ok=True)
    
    generator = ReportGenerator(results, args.output, scan_id, logger)

    if args.format in ("json", "both"):
        json_path = generator.generate_json()
        logger.info(f"[+] JSON report   : {json_path}")

    if args.format in ("pdf", "both"):
        pdf_path = generator.generate_pdf()
        logger.info(f"[+] PDF report    : {pdf_path}")

    logger.info("")
    logger.info("[✓] AutoVAPT scan completed successfully.")
    logger.info(f"[✓] Reports saved to: {os.path.abspath(args.output)}")


def main():
    args = parse_args()
    print_banner()

    # Setup
    config = Config(args.config)
    os.makedirs("logs", exist_ok=True)
    os.makedirs(args.output, exist_ok=True)

    log_file = os.path.join("logs", f"autovapt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    logger = setup_logger(verbose=args.verbose, log_file=log_file)

    logger.info(f"[*] Log file: {log_file}")

    try:
        run_pipeline(args, logger, config)
    except KeyboardInterrupt:
        logger.warning("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[✗] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
