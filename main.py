import argparse
import sys
from secureops.scanner import ScannerOrchestrator
from secureops.parser import Parser
from secureops.scorer import Scorer
from secureops.reporter import Reporter


def main():
    parser = argparse.ArgumentParser(
        description="SecureOps AI - Local DevSecOps Security Scanner"
    )
    parser.add_argument(
        "path",
        help="Path to target project directory"
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
    # Report
    # -------------------------
    reporter = Reporter(parsed, score_data, tools_used)
    reporter.print_summary()
    reporter.save_json_report()


if __name__ == "__main__":
    main()
