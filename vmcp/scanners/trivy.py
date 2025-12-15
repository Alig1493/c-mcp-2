"""Trivy scanner implementation."""
import asyncio
import json
import subprocess
from datetime import datetime
from typing import Any

from vmcp.models import (
    VulnerabilityModel,
    VulnerabilityReferenceModel,
    VulnerabilityScoreModel,
)
from vmcp.scanners.base import BaseScanner


class TrivyScanner(BaseScanner):
    """Trivy vulnerability scanner."""

    @property
    def name(self) -> str:
        return "trivy"

    async def scan(self) -> list[VulnerabilityModel]:
        """Execute Trivy scan."""
        try:
            # Run trivy scan
            result = subprocess.run(
                [
                    'trivy',
                    'fs',
                    '--format', 'json',
                    '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                    self.repo_path
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0 and not result.stdout:
                return []

            data = json.loads(result.stdout)
            return self._parse_trivy_output(data)

        except subprocess.TimeoutExpired:
            print(f"Trivy scan timed out for {self.repo_path}")
            return []
        except Exception as e:
            print(f"Trivy scan failed: {e}")
            return []

    def _parse_trivy_output(self, data: dict[str, Any]) -> list[VulnerabilityModel]:
        """Parse Trivy JSON output."""
        vulnerabilities = []

        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                # Parse references
                references = []
                for ref in vuln.get('References', []):
                    references.append(
                        VulnerabilityReferenceModel(
                            type='web',
                            url=ref
                        )
                    )

                # Parse scores
                scores = []
                if 'CVSS' in vuln:
                    for version, score_data in vuln['CVSS'].items():
                        if isinstance(score_data, dict) and 'V3Score' in score_data:
                            scores.append(
                                VulnerabilityScoreModel(
                                    type='cvss',
                                    value=score_data['V3Score'],
                                    version=version
                                )
                            )

                # Parse published date
                published = None
                if 'PublishedDate' in vuln:
                    try:
                        published = datetime.fromisoformat(
                            vuln['PublishedDate'].replace('Z', '+00:00')
                        )
                    except Exception:
                        pass

                vulnerability = VulnerabilityModel(
                    id=vuln.get('VulnerabilityID', ''),
                    identifier_type='cve' if vuln.get('VulnerabilityID', '').startswith('CVE') else 'other',
                    affected_range=vuln.get('InstalledVersion', ''),
                    aliases=[],
                    details=vuln.get('Description', ''),
                    fixed_version=vuln.get('FixedVersion'),
                    published=published,
                    references=references,
                    scores=scores,
                    severity=vuln.get('Severity', 'UNKNOWN'),
                    source='trivy',
                    summary=vuln.get('Title', ''),
                )

                vulnerabilities.append(vulnerability)

        return vulnerabilities
