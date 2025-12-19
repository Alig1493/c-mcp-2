"""OSV Scanner implementation."""
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


class OSVScanner(BaseScanner):
    """OSV vulnerability scanner."""

    @property
    def name(self) -> str:
        return "osv-scanner"

    async def scan(self) -> list[VulnerabilityModel]:
        """Execute OSV scan."""
        try:
            result = subprocess.run(
                ['osv-scanner', '--format', 'json', '--recursive', self.repo_path],
                capture_output=True,
                text=True,
                timeout=300
            )

            # OSV scanner returns non-zero if vulnerabilities found
            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            return self._parse_osv_output(data)

        except subprocess.TimeoutExpired:
            print(f"OSV scan timed out for {self.repo_path}")
            return []
        except Exception as e:
            print(f"OSV scan failed: {e}")
            return []

    def _parse_osv_output(self, data: dict[str, Any]) -> list[VulnerabilityModel]:
        """Parse OSV JSON output."""
        vulnerabilities = []

        for result in data.get('results', []):
            for package in result.get('packages', []):
                for vuln in package.get('vulnerabilities', []):
                    # Parse references
                    references = []
                    for ref in vuln.get('references', []):
                        references.append(
                            VulnerabilityReferenceModel(
                                type=ref.get('type', 'web'),
                                url=ref.get('url', '')
                            )
                        )

                    # Parse scores
                    scores = []
                    if 'severity' in vuln:
                        for severity in vuln['severity']:
                            if severity.get('type') == 'CVSS_V3':
                                scores.append(
                                    VulnerabilityScoreModel(
                                        type='cvss',
                                        value=float(severity.get('score', 0)),
                                        version='3.0'
                                    )
                                )

                    # Parse published date
                    published = None
                    if 'published' in vuln:
                        try:
                            published = datetime.fromisoformat(
                                vuln['published'].replace('Z', '+00:00')
                            )
                        except Exception:
                            pass

                    # Determine severity and normalize it
                    severity = vuln.get('database_specific', {}).get('severity', 'UNKNOWN').upper()

                    # Map OSV severity values to our standard severity levels
                    severity_map = {
                        'MODERATE': 'MEDIUM',  # OSV uses MODERATE, we use MEDIUM
                        'CRITICAL': 'CRITICAL',
                        'HIGH': 'HIGH',
                        'MEDIUM': 'MEDIUM',
                        'LOW': 'LOW',
                        'UNKNOWN': 'UNKNOWN',
                    }
                    severity = severity_map.get(severity, 'UNKNOWN')

                    vulnerability = VulnerabilityModel(
                        id=vuln.get('id', ''),
                        identifier_type='cve' if vuln.get('id', '').startswith('CVE') else 'other',
                        affected_range=vuln.get('affected', [{}])[0].get('ranges', [{}])[0].get('events', [{}])[0].get('introduced', '') if vuln.get('affected') else '',
                        aliases=vuln.get('aliases', []),
                        details=vuln.get('details', ''),
                        fixed_version=vuln.get('affected', [{}])[0].get('ranges', [{}])[0].get('events', [{}])[-1].get('fixed') if vuln.get('affected') else None,
                        published=published,
                        references=references,
                        scores=scores,
                        severity=severity,
                        source='osv',
                        summary=vuln.get('summary', ''),
                    )

                    vulnerabilities.append(vulnerability)

        return vulnerabilities
