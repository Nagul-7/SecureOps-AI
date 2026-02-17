from typing import List, Dict


class Scorer:
    """
    Normalizes severities and computes risk score + grade.
    """

    SEVERITY_MAP = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    def __init__(self, findings: List[Dict]):
        self.findings = findings

    def normalize_severity(self, severity: str) -> str:
        if not severity:
            return "LOW"

        severity = severity.upper()

        if "CRITICAL" in severity:
            return "CRITICAL"
        if "HIGH" in severity:
            return "HIGH"
        if "MEDIUM" in severity:
            return "MEDIUM"
        if "LOW" in severity:
            return "LOW"

        return "LOW"

    def calculate_grade(self, score: float) -> str:
        if score <= 2:
            return "A"
        elif score <= 4:
            return "B"
        elif score <= 6:
            return "C"
        elif score <= 8:
            return "D"
        else:
            return "F"

    def score(self) -> Dict:
        total = len(self.findings)

        if total == 0:
            return {
                "total_findings": 0,
                "severity_breakdown": {},
                "risk_score": 0,
                "risk_grade": "A"
            }

        breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        total_weight = 0

        for finding in self.findings:
            normalized = self.normalize_severity(finding.get("severity"))
            finding["severity"] = normalized

            breakdown[normalized] += 1
            total_weight += self.SEVERITY_MAP[normalized]

        risk_score = round(total_weight / total, 2)
        risk_grade = self.calculate_grade(risk_score)

        return {
            "total_findings": total,
            "severity_breakdown": breakdown,
            "risk_score": risk_score,
            "risk_grade": risk_grade
        }
