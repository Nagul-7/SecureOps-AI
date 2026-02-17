import shutil
import difflib
from pathlib import Path
from typing import List, Dict
from datetime import datetime


class Fixer:
    """
    Hardened structured auto-fix engine.
    - Groups fixes per file
    - Single backup per file
    - Diff preview before apply
    - Tracks statistics
    """

    def __init__(self, findings: List[Dict]):
        self.findings = findings
        self.stats = {
            "auto_fixable": 0,
            "files_modified": 0,
            "fixes_applied": 0,
            "fixes_skipped": 0
        }

    def apply_fixes(self):
        file_map = {}

        for f in self.findings:
            if f.get("auto_fix_possible"):
                self.stats["auto_fixable"] += 1
                file_map.setdefault(f["file"], []).append(f)

        if not file_map:
            print("No auto-fixable issues found.")
            return

        for file_path, issues in file_map.items():
            self._process_file(file_path, issues)

        self._print_stats()

    # --------------------------------------------------
    # Process Per File
    # --------------------------------------------------

    def _process_file(self, file_path: str, issues: List[Dict]):
        path = Path(file_path)

        if not path.exists():
            print(f"[!] File not found: {file_path}")
            return

        original_lines = path.read_text().splitlines()
        modified_lines = original_lines.copy()

        modified = False

        for issue in issues:
            line_index = issue["line"] - 1
            issue_text = issue["issue"].lower()

            if line_index < 0 or line_index >= len(modified_lines):
                continue

            original_line = modified_lines[line_index]
            new_line = original_line

            # Hardcoded secret
            if "hardcoded" in issue_text or "password" in issue_text:
                new_line = 'password = os.getenv("PASSWORD")'

            # subprocess shell=True
            elif "shell=true" in issue_text or "subprocess" in issue_text:
                new_line = original_line.replace("shell=True", "shell=False")

            # debug mode
            elif "debug" in issue_text:
                new_line = original_line.replace("debug=True", "debug=False")

            if new_line != original_line:
                modified_lines[line_index] = new_line
                modified = True
                self.stats["fixes_applied"] += 1
            else:
                self.stats["fixes_skipped"] += 1

        if not modified:
            return

        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile="before",
            tofile="after",
            lineterm=""
        )

        print("\n".join(diff))

        confirm = input("Apply these fixes? (Y/N): ").strip().lower()

        if confirm != "y":
            print("Skipped file.")
            self.stats["fixes_skipped"] += 1
            return

        # Unique timestamped backup
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = path.with_suffix(path.suffix + f".bak_{timestamp}")
        shutil.copy(path, backup_path)

        path.write_text("\n".join(modified_lines))

        print(f"[+] Backup created: {backup_path}")
        print(f"[+] Fixes applied to {file_path}")

        self.stats["files_modified"] += 1

    # --------------------------------------------------
    # Stats
    # --------------------------------------------------

    def _print_stats(self):
        print("\n========== Fix Summary ==========")
        for k, v in self.stats.items():
            print(f"{k.replace('_',' ').title():<20}: {v}")
        print("=================================\n")
