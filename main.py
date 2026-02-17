import argparse
import sys
import time
from datetime import datetime, UTC

from secureops.scanner import ScannerOrchestrator
from secureops.parser import Parser
from secureops.scorer import Scorer
from secureops.reporter import Reporter
from secureops.analyzer import Analyzer
from secureops.fixer import Fixer


def main():
    parser = argparse.ArgumentParser(
        description="SecureOps AI - Local DevSecOps Security Scanner"
    )

    parser.add_argument(
        "path",
        help="Path to target project directory"
    )

    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Automatically apply safe fixes"
    )

    args = parser.parse_args()
    target_path = args.path

    scan_start_time = datetime.now(UTC)
    start_timer = time.time()

    # -------------------------
    # Run Scanners
    # -------------------------
    orchestrator = ScannerOrchestrator(target_path)
    raw_results = orchestrator.run()

    if not raw_results:
        print("No supported languages detected or no findings.")
        sys.exit(0)

    tools_used = [result["tool"] for result in raw_results]

    # -------------------------
    # Parse Results
    # -------------------------
    parsed = Parser(raw_results).parse()

    # -------------------------
    # Score Findings
    # -------------------------
    score_data = Scorer(parsed).score()

    # -------------------------
    # Analyze Findings
    # -------------------------
    analyzed = Analyzer(parsed).analyze()

    scan_end_time = datetime.now(UTC)
    duration = round(time.time() - start_timer, 2)

    metadata = orchestrator.get_metadata()
    metadata.update({
        "scan_started_at": scan_start_time.isoformat(),
        "scan_completed_at": scan_end_time.isoformat(),
        "duration_seconds": duration,
        "tools_used": tools_used
    })

    # -------------------------
    # Reporting
    # -------------------------
    reporter = Reporter(analyzed, score_data, metadata)
    reporter.print_summary()
    reporter.save_json_report()

    # -------------------------
    # Optional Auto Fix
    # -------------------------
    if args.auto_fix:
        print("\n[*] Auto-fix mode enabled.")
        Fixer(analyzed).apply_fixes()
    else:
        print("\n[*] Run with --auto-fix to apply safe fixes.")


if __name__ == "__main__":
    main()
