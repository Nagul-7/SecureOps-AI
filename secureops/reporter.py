import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict


class Reporter:
    """
    Handles terminal output and JSON report generation.
    """

    def __init__(self, findings: List[Dict], score_data: Dict, tools_used: List[str]):
        self.findings = findings
        self.score_data = score_data
        self.tools_used = tools_used
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)

    # -------------------------
    # Terminal Summary
    # -------------------------
    def print_summary(self):
        print("\n========== SecureOps AI Report ==========")
        print(f"Total Findings : {self.score_data['total_findings']}")
        print("Severity Breakdown:")

        for severity, count in self.score_data["severity_breakdown"].items():
            print(f"  {severity:<8}: {count}")

        print(f"Risk Score      : {self.score_data['risk_score']}")
        print(f"Risk Grade      : {self.score_data['risk_grade']}")
        print(f"Tools Used      : {', '.join(self.tools_used)}")
        print("=========================================\n")

    # -------------------------
    # JSON Report
    # -------------------------
    def save_json_report(self) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        report_data = {
            "generated_at": timestamp,
            "tools_used": self.tools_used,
            "summary": self.score_data,
            "findings": self.findings
        }

        report_path = self.report_dir / f"report_{timestamp}.json"

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=4)

        print(f"[+] Report saved to {report_path}")

        return str(report_path)
