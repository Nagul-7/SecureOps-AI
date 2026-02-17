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
