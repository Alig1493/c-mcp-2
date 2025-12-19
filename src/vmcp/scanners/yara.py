"""YARA scanner implementation for malware and threat detection."""
import os
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from vmcp.models import VulnerabilityModel, VulnerabilityReferenceModel
from vmcp.scanners.base import BaseScanner


class YaraScanner(BaseScanner):
    """YARA malware and threat detection scanner."""

    def __init__(self, repo_path: str, org_name: str, repo_name: str):
        super().__init__(repo_path, org_name, repo_name)
        # Path to YARA rules file (relative to this file: ../../../../yara-forge-rules-core/)
        self.rules_path = (Path(__file__).parent / "../../../yara-forge-rules-core/yara-rules-core.yar").resolve()
        self.max_file_size = 10 * 1024 * 1024  # 10MB limit per file

    @property
    def name(self) -> str:
        return "yara"

    async def scan(self) -> list[VulnerabilityModel]:
        """Execute YARA scan on repository."""
        if not YARA_AVAILABLE:
            print("YARA is not installed. Please install yara-python: pip install yara-python")
            return []

        if not self.rules_path.exists():
            print(f"YARA rules not found at {self.rules_path}")
            return []

        try:
            # Compile YARA rules
            print(f"Compiling YARA rules from {self.rules_path}...")
            rules = yara.compile(filepath=str(self.rules_path))
            print("YARA rules compiled successfully")

            vulnerabilities = []

            # Recursively scan all files in repository
            for root, dirs, files in os.walk(self.repo_path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]

                for filename in files:
                    filepath = os.path.join(root, filename)

                    # Skip large files
                    try:
                        if os.path.getsize(filepath) > self.max_file_size:
                            continue
                    except OSError:
                        continue

                    # Scan file with YARA rules
                    try:
                        matches = rules.match(filepath)
                        for match in matches:
                            # Convert absolute path to relative path for consistency
                            relative_path = os.path.relpath(filepath, self.repo_path)
                            vuln = self._parse_yara_match(match, relative_path)
                            vulnerabilities.append(vuln)
                    except yara.Error:
                        # Skip files that can't be scanned (permission errors, binary issues, etc.)
                        continue
                    except Exception:
                        # Skip any other errors
                        continue

            print(f"YARA scan complete. Found {len(vulnerabilities)} matches.")
            return vulnerabilities

        except yara.SyntaxError as e:
            print(f"YARA rule compilation error: {e}")
            return []
        except Exception as e:
            print(f"YARA scan failed: {e}")
            return []

    def _parse_yara_match(self, match: Any, filepath: str) -> VulnerabilityModel:
        """Convert YARA match to VulnerabilityModel with rich context."""

        # Extract metadata from rule
        meta = match.meta
        description = meta.get('description', 'No description available')
        author = meta.get('author', 'Unknown')
        rule_id = meta.get('id', '')
        reference = meta.get('reference', '')
        source_url = meta.get('source_url', '')
        score = int(meta.get('score', 70))
        date = meta.get('date', '2024-01-01')

        # Get tags
        tags = list(match.tags) if match.tags else []

        # Build detailed explanation with matched strings
        matched_strings = []
        if match.strings:
            for s in match.strings[:3]:  # Limit to first 3 matches
                if s.instances:
                    offset = s.instances[0].offset
                    matched_strings.append(f"${s.identifier} at offset {hex(offset)}")

        match_details = f"{description}"
        if matched_strings:
            match_details += f" Rule triggered because: Matched strings: {', '.join(matched_strings)}."

        # Map severity from score and tags
        severity = self._map_yara_severity(score, tags)

        # Build references
        references = []
        if reference:
            references.append(VulnerabilityReferenceModel(type='web', url=reference))
        if source_url:
            references.append(VulnerabilityReferenceModel(type='web', url=source_url))

        # Get line range from first match offset (if available)
        line_range = ""
        if match.strings and match.strings[0].instances:
            offset = match.strings[0].instances[0].offset
            line_range = self._offset_to_line_range(filepath, offset)

        # Parse date safely
        try:
            published_date = datetime.fromisoformat(date)
        except (ValueError, TypeError):
            published_date = None

        # Determine confidence based on score
        confidence = 'HIGH' if score >= 80 else 'MEDIUM' if score >= 70 else 'LOW'

        return VulnerabilityModel(
            id=match.rule,
            identifier_type='yara_rule',
            rule_name=match.rule,
            rule_id=rule_id,
            severity=severity,
            details=match_details,
            summary=description[:100] if len(description) > 100 else description,
            file_location=filepath,
            line_range=line_range,
            categories=tags,
            references=references,
            confidence=confidence,
            affected_range='',
            fixed_version=None,
            published=published_date,
            aliases=[],
            scores=[],
            source=None
        )

    def _map_yara_severity(self, score: int, tags: list[str]) -> str:
        """Map YARA rule score and tags to severity level."""
        # Check for critical tags
        critical_tags = {'MALWARE', 'RANSOMWARE', 'BACKDOOR', 'TROJAN'}
        high_tags = {'EXPLOIT', 'SHELLCODE', 'SUSPICIOUS', 'WEBSHELL'}

        # Convert tags to uppercase for comparison
        tags_upper = {tag.upper() for tag in tags}

        if any(tag in critical_tags for tag in tags_upper) or score >= 90:
            return 'CRITICAL'
        elif any(tag in high_tags for tag in tags_upper) or score >= 75:
            return 'HIGH'
        elif score >= 65:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _offset_to_line_range(self, filepath: str, offset: int) -> str:
        """Convert byte offset to line number range.

        Args:
            filepath: Relative path from repo root
            offset: Byte offset in the file
        """
        try:
            # Convert relative path to absolute for file reading
            abs_filepath = os.path.join(self.repo_path, filepath)

            with open(abs_filepath, 'rb') as f:
                content = f.read(offset + 1000)  # Read a bit more for context

            # Count newlines up to offset
            line_number = content[:offset].count(b'\n') + 1

            # Estimate line range (match might span multiple lines)
            end_line = line_number + 5  # Assume match spans ~5 lines

            return f"{line_number}-{end_line}"
        except Exception:
            return "1-1"
