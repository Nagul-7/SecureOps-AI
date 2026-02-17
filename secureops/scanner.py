import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict


class ScannerOrchestrator:
    """
    Orchestrates language detection and routes to appropriate security scanners.
    """

    def __init__(self, target_path: str):
        self.target_path = Path(target_path).resolve()
        self.detected_languages = set()
        self.results = []

    # -------------------------
    # Language Detection
    # -------------------------
    def detect_languages(self) -> List[str]:
        """
        Detects project languages based on file patterns.
        """
        for root, dirs, files in os.walk(self.target_path):
            for file in files:
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
        """
        Main execution method.
        """
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
        """
        Runs Bandit for Python projects.
        """
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
        """
        Runs Semgrep for NodeJS / Go.
        """
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
        """
        Runs Trivy for Dockerfile scanning.
        """
        print("[*] Running Trivy (Dockerfile)...")

        cmd = [
            "trivy",
            "config",
            "--format",
            "
