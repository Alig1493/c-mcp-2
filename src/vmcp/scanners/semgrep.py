"""Semgrep scanner implementation."""
import json
import subprocess
from typing import Any

from vmcp.models import VulnerabilityModel, VulnerabilityReferenceModel
from vmcp.scanners.base import BaseScanner


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner."""

    @property
    def name(self) -> str:
        return "semgrep"

    async def scan(self) -> list[VulnerabilityModel]:
        """Execute Semgrep scan."""
        try:
            result = subprocess.run(
                [
                    'semgrep',
                    '--config', 'auto',
                    '--json',
                    '--quiet',
                    self.repo_path
                ],
                capture_output=True,
                text=True,
                timeout=600
            )

            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            return self._parse_semgrep_output(data)

        except subprocess.TimeoutExpired:
            print(f"Semgrep scan timed out for {self.repo_path}")
            return []
        except Exception as e:
            print(f"Semgrep scan failed: {e}")
            return []

    def _parse_semgrep_output(self, data: dict[str, Any]) -> list[VulnerabilityModel]:
        """Parse Semgrep JSON output."""
        from pathlib import Path

        vulnerabilities = []

        for result in data.get('results', []):
            # Parse references
            references = []
            for ref_url in result.get('extra', {}).get('metadata', {}).get('references', []):
                references.append(
                    VulnerabilityReferenceModel(type='web', url=ref_url)
                )

            # Map Semgrep severity to our severity levels
            semgrep_severity = result.get('extra', {}).get('severity', 'WARNING')
            severity_map = {
                'ERROR': 'HIGH',
                'WARNING': 'MEDIUM',
                'INFO': 'LOW',
            }
            severity = severity_map.get(semgrep_severity, 'MEDIUM')

            # Get CWE categories
            categories = result.get('extra', {}).get('metadata', {}).get('cwe', [])
            if isinstance(categories, str):
                categories = [categories]

            # Normalize file path to be relative to repo root
            file_path = result.get('path', '')
            if file_path:
                try:
                    # If path is absolute, make it relative to repo_path
                    abs_path = Path(file_path)
                    if abs_path.is_absolute():
                        file_path = str(abs_path.relative_to(self.repo_path))
                except (ValueError, AttributeError):
                    # If relative_to fails, path might already be relative
                    pass

            vulnerability = VulnerabilityModel(
                id=result.get('check_id', ''),
                identifier_type='semgrep_rule',
                affected_range='',
                aliases=[],
                details=result.get('extra', {}).get('message', ''),
                fixed_version=None,
                published=None,
                references=references,
                scores=[],
                severity=severity,
                source=None,
                summary=result.get('extra', {}).get('metadata', {}).get('message', result.get('check_id', '')),
                # SAST-specific fields
                rule_name=result.get('check_id', ''),
                rule_id=result.get('check_id', ''),
                confidence=result.get('extra', {}).get('metadata', {}).get('confidence', 'MEDIUM'),
                file_location=file_path,
                line_range=f"{result.get('start', {}).get('line', '')}-{result.get('end', {}).get('line', '')}",
                categories=categories,
            )

            vulnerabilities.append(vulnerability)

        return vulnerabilities
