from typing import List, Dict


class Parser:
    """
    Converts raw scanner outputs into standardized schema.
    """

    def __init__(self, scanner_results: List[Dict]):
        self.scanner_results = scanner_results

    def parse(self) -> List[Dict]:
        standardized = []

        for result in self.scanner_results:
            tool = result.get("tool")
            language = result.get("language")
            raw = result.get("raw")

            if tool == "bandit":
                standardized.extend(self._parse_bandit(raw, language))

            elif tool == "semgrep":
                standardized.extend(self._parse_semgrep(raw, language))

            elif tool == "trivy":
                standardized.extend(self._parse_trivy(raw, language))

            elif tool == "checkov":
                standardized.extend(self._parse_checkov(raw, language))

        return standardized

    # -------------------------
    # Tool Parsers
    # -------------------------

    def _parse_bandit(self, raw: Dict, language: str) -> List[Dict]:
        findings = []

        for issue in raw.get("results", []):
            findings.append({
                "file": issue.get("filename"),
                "line": issue.get("line_number"),
                "issue": issue.get("issue_text"),
                "severity": issue.get("issue_severity"),
                "tool": "bandit",
                "language": language
            })

        return findings

    def _parse_semgrep(self, raw: Dict, language: str) -> List[Dict]:
        findings = []

        for issue in raw.get("results", []):
            findings.append({
                "file": issue.get("path"),
                "line": issue.get("start", {}).get("line"),
                "issue": issue.get("extra", {}).get("message"),
                "severity": issue.get("extra", {}).get("severity"),
                "tool": "semgrep",
                "language": language
            })

        return findings

    def _parse_trivy(self, raw: Dict, language: str) -> List[Dict]:
        findings = []

        for result in raw.get("Results", []):
            for misconf in result.get("Misconfigurations", []):
                findings.append({
                    "file": result.get("Target"),
                    "line": misconf.get("StartLine"),
                    "issue": misconf.get("Title"),
                    "severity": misconf.get("Severity"),
                    "tool": "trivy",
                    "language": language
                })

        return findings

    def _parse_checkov(self, raw: Dict, language: str) -> List[Dict]:
        findings = []

        for issue in raw.get("results", {}).get("failed_checks", []):
            findings.append({
                "file": issue.get("file_path"),
                "line": issue.get("file_line_range", [None])[0],
                "issue": issue.get("check_name"),
                "severity": issue.get("severity"),
                "tool": "checkov",
                "language": language
            })

        return findings
