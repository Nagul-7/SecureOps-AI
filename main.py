import argparse
import sys
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

    # -------------------------
    # Reporting
    # -------------------------
    reporter = Reporter(analyzed, score_data, tools_used)
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
