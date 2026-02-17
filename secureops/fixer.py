import shutil
import difflib
from pathlib import Path
from typing import List, Dict


class Fixer:
    """
    Applies safe structured fixes based on analyzer output.
    """

    def __init__(self, findings: List[Dict]):
        self.findings = findings

    def apply_fixes(self):
        applicable = [f for f in self.findings if f.get("auto_fix_possible")]

        if not applicable:
            print("No auto-fixable issues found.")
            return

        for finding in applicable:
            self._fix_finding(finding)

    # --------------------------------------------------
    # Core Fix Logic
    # --------------------------------------------------

    def _fix_finding(self, finding: Dict):
        file_path = Path(finding["file"])

        if not file_path.exists():
            print(f"[!] File not found: {file_path}")
            return

        original_lines = file_path.read_text().splitlines()
        modified_lines = original_lines.copy()

        line_index = finding["line"] - 1
        issue_text = finding["issue"].lower()

        if line_index < 0 or line_index >= len(original_lines):
            print("[!] Invalid line number.")
            return

        original_line = original_lines[line_index]
        modified_line = original_line

        # -------------------------
        # Hardcoded Secret Fix
        # -------------------------
        if "hardcoded" in issue_text or "password" in issue_text:
            modified_line = 'password = os.getenv("PASSWORD")'

        # -------------------------
        # subprocess shell=True Fix
        # -------------------------
        elif "shell=true" in issue_text or "subprocess" in issue_text:
            modified_line = original_line.replace("shell=True", "shell=False")

        # -------------------------
        # Debug Mode Fix
        # -------------------------
        elif "debug" in issue_text:
            modified_line = original_line.replace("debug=True", "debug=False")

        if modified_line == original_line:
            print("[*] No safe modification pattern matched.")
            return

        modified_lines[line_index] = modified_line

        # Show diff
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile="before",
            tofile="after",
            lineterm=""
        )

        print("\n".join(diff))

        confirm = input("Apply this fix? (Y/N): ").strip().lower()

        if confirm != "y":
            print("Skipped.")
            return

        # Backup
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        shutil.copy(file_path, backup_path)
        print(f"[+] Backup created: {backup_path}")

        # Write changes
        file_path.write_text("\n".join(modified_lines))
        print(f"[+] Fix applied to {file_path}")
