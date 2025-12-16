"""Scan orchestrator for running multiple scanners in parallel."""
import asyncio
import json
from pathlib import Path
from typing import Any

from vmcp.models import VulnerabilityModel
from vmcp.scanners import OSVScanner, SemgrepScanner, TrivyScanner
from vmcp.scanners.base import BaseScanner


class ScanOrchestrator:
    """Orchestrates multiple vulnerability scanners."""

    SCANNER_MAP = {
        'trivy': TrivyScanner,
        'osv-scanner': OSVScanner,
        'semgrep': SemgrepScanner,
    }

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
            scanner_names = list(self.SCANNER_MAP.keys())

        # Filter to only valid scanners
        scanner_classes = [
            self.SCANNER_MAP[name]
            for name in scanner_names
            if name in self.SCANNER_MAP
        ]

        # Run all scanners in parallel
        tasks = [self.run_scanner(scanner_class) for scanner_class in scanner_classes]
        results = await asyncio.gather(*tasks)

        return dict(results)

    def save_results(self, results: dict[str, list[VulnerabilityModel]], output_dir: str) -> None:
        """Save scan results to JSON file."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for scanner, vulnerabilities in results.items():
            # Format results
            formatted_results = {
                f"{self.org_name}/{self.repo_name}": {
                    scanner: [vuln.model_dump(mode='json') for vuln in vulnerabilities]
                }
            }

            # Save scanner-specific temp file to results directory
            violations_file = output_path / f'{scanner}-violations.json'
            with open(violations_file, 'w') as f:
                json.dump(formatted_results, f, indent=2, default=str)

            print(f"Results saved to {violations_file}")
