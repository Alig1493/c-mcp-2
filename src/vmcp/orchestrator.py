"""Scan orchestrator for running multiple scanners in parallel."""
import asyncio
import json
from pathlib import Path
from typing import Any

from vmcp.models import VulnerabilityModel
from vmcp.scanners import OSVScanner, SemgrepScanner, TrivyScanner
from vmcp.scanners.yara import YaraScanner
from vmcp.scanners.base import BaseScanner

SCANNER_MAP = {
    'trivy': TrivyScanner,
    'osv-scanner': OSVScanner,
    'semgrep': SemgrepScanner,
    'yara': YaraScanner,
}


class ScanOrchestrator:
    """Orchestrates multiple vulnerability scanners."""

    def __init__(self, repo_path: str, org_name: str, repo_name: str):
        self.repo_path = repo_path
        self.org_name = org_name
        self.repo_name = repo_name

    async def run_scanner(self, scanner_class: type[BaseScanner]) -> tuple[str, list[VulnerabilityModel]]:
        """Run a single scanner."""
        scanner = scanner_class(self.repo_path, self.org_name, self.repo_name)

        if not scanner.is_applicable():
            return scanner.name, []

        try:
            vulnerabilities = await scanner.scan()
            return scanner.name, vulnerabilities
        except Exception as e:
            print(f"Error running {scanner.name}: {e}")
            return scanner.name, []

    async def run_all_scanners(self, scanner_names: list[str] | None = None) -> dict[str, list[VulnerabilityModel]]:
        """Run all scanners in parallel."""
        if scanner_names is None:
            scanner_names = list(SCANNER_MAP.keys())

        # Filter to only valid scanners
        scanner_classes = [
            SCANNER_MAP[name]
            for name in scanner_names
            if name in SCANNER_MAP
        ]

        # Run all scanners in parallel
        tasks = [self.run_scanner(scanner_class) for scanner_class in scanner_classes]
        results = await asyncio.gather(*tasks)

        return dict(results)

    def save_results(self, results: dict[str, list[VulnerabilityModel]], output_dir: str) -> None:
        """Save scan results to JSON file in new simplified format."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Format results: {"scanner": [vulns]}
        formatted_results = {
            scanner: [vuln.model_dump(mode='json') for vuln in vulnerabilities]
            for scanner, vulnerabilities in results.items()
        }

        # Save to scanner-specific temp file
        for scanner in results.keys():
            scanner_file = output_path / f'{scanner}-violations.json'
            with open(scanner_file, 'w') as f:
                json.dump({scanner: formatted_results[scanner]}, f, indent=2, default=str)
            print(f"Results saved to {scanner_file}")
