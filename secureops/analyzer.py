from typing import List, Dict


class Analyzer:
    """
    Adds structured intelligence to normalized findings.
    Rule-based. Offline. Deterministic.
    """

    def __init__(self, findings: List[Dict]):
        self.findings = findings

    def analyze(self) -> List[Dict]:
        enriched = []

        for finding in self.findings:
            enriched_finding = finding.copy()

            rule_data = self._apply_rules(finding)

            enriched_finding.update(rule_data)

            enriched.append(enriched_finding)

        return enriched

    # --------------------------------------------------
    # Rule Engine
    # --------------------------------------------------

    def _apply_rules(self, finding: Dict) -> Dict:
        issue_text = (finding.get("issue") or "").lower()

        # Default values
        explanation = "No detailed explanation available."
        risk_reason = "Potential security weakness."
        recommended_fix = "Review the code and apply secure coding practices."
        auto_fix_possible = False

        # -------------------------
        # Hardcoded Secrets
        # -------------------------
        if "hardcoded" in issue_text or "password" in issue_text:
            explanation = (
                "Hardcoded secrets expose sensitive credentials directly "
                "in source code."
            )
            risk_reason = (
                "If repository is leaked or shared, attackers gain access "
                "to credentials immediately."
            )
            recommended_fix = (
                "Move secrets to environment variables or a secure vault."
            )
            auto_fix_possible = True

        # -------------------------
        # subprocess shell=True
        # -------------------------
        elif "shell=true" in issue_text or "subprocess" in issue_text:
            explanation = (
                "Using subprocess with shell=True can allow command injection."
            )
            risk_reason = (
                "User-controlled input may execute arbitrary system commands."
            )
            recommended_fix = (
                "Avoid shell=True. Pass command as list and validate inputs."
            )
            auto_fix_possible = True

        # -------------------------
        # Debug Mode Enabled
        # -------------------------
        elif "debug" in issue_text:
            explanation = (
                "Debug mode exposes internal application state."
            )
            risk_reason = (
                "Attackers may retrieve sensitive stack traces or environment details."
            )
            recommended_fix = (
                "Disable debug mode in production environments."
            )
            auto_fix_possible = True

        return {
            "explanation": explanation,
            "risk_reason": risk_reason,
            "recommended_fix": recommended_fix,
            "auto_fix_possible": auto_fix_possible
        }
