import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict


class ScannerOrchestrator:
    """
    Orchestrates language detection and routes to appropriate security scanners.
    Tracks metadata for reporting.
    """

    def __init__(self, target_path: str):
        self.target_path = Path(target_path).resolve()
        self.detected_languages = set()
        self.results = []
        self.files_scanned = 0

    # -------------------------
    # Language Detection
    # -------------------------
    def detect_languages(self) -> List[str]:
        """
        Detects project languages and counts scanned files.
        """
        for root, dirs, files in os.walk(self.target_path):
            for file in files:
                self.files_scanned += 1

                if file.endswith(".py"):
                    self.detected_languages.add("python")

                if file == "package.json":
                    self.detected_languages.add("node")

                if file == "go.mod":
                    self.detected_languages.add("go")

                if file == "Dockerfile":
                    self.detected_languages.add("docker")

                if file.endswith(".tf"):
                    self.detected_languages.add("terraform")

        return list(self.detected_languages)

    # -------------------------
    # Scanner Routing
    # -------------------------
    def run(self) -> List[Dict]:
        languages = self.detect_languages()

        if "python" in languages:
            self.run_bandit()

        if "node" in languages or "go" in languages:
            self.run_semgrep()

        if "docker" in languages:
            self.run_trivy()

        if "terraform" in languages:
            self.run_checkov()

        return self.results

    # -------------------------
    # Tool Runners
    # -------------------------
    def run_bandit(self):
        print("[*] Running Bandit (Python)...")

        cmd = [
            "bandit",
            "-r",
            str(self.target_path),
            "-f",
            "json"
        ]

        output = self._execute_command(cmd)
        if output:
            self.results.append({
                "tool": "bandit",
                "language": "python",
                "raw": output
            })

    def run_semgrep(self):
        print("[*] Running Semgrep (Multi-language)...")

        cmd = [
            "semgrep",
            "--config=auto",
            "--json",
            str(self.target_path)
        ]

        output = self._execute_command(cmd)
        if output:
            self.results.append({
                "tool": "semgrep",
                "language": "multi",
                "raw": output
            })

    def run_trivy(self):
        print("[*] Running Trivy (Dockerfile)...")

        cmd = [
            "trivy",
            "config",
            "--format",
            "json",
            str(self.target_path)
        ]

        output = self._execute_command(cmd)
        if output:
            self.results.append({
                "tool": "trivy",
                "language": "docker",
                "raw": output
            })

    def run_checkov(self):
        print("[*] Running Checkov (Terraform)...")

        cmd = [
            "checkov",
            "-d",
            str(self.target_path),
            "--output",
            "json"
        ]

        output = self._execute_command(cmd)
        if output:
            self.results.append({
                "tool": "checkov",
                "language": "terraform",
                "raw": output
            })

    # -------------------------
    # Metadata Getter
    # -------------------------
    def get_metadata(self) -> Dict:
        return {
            "languages_detected": list(self.detected_languages),
            "files_scanned": self.files_scanned
        }

    # -------------------------
    # Safe Command Execution
    # -------------------------
    def _execute_command(self, cmd: List[str]) -> Dict:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            if result.stdout:
                return json.loads(result.stdout)

            return None

        except json.JSONDecodeError:
            print("[!] Failed to parse JSON output.")
            return None

        except Exception as e:
            print(f"[!] Scanner execution error: {e}")
            return None
