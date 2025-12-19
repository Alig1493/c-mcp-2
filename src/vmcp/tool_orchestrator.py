"""Tool-based scan orchestrator for MCP servers.

Groups vulnerability scan results by MCP tools instead of by scanner.
Format: {"scanner": {"tool_name": [vulnerabilities]}}
"""
import asyncio
import json
from pathlib import Path
from typing import Any

from vmcp.models import VulnerabilityModel
from vmcp.orchestrator import SCANNER_MAP, ScanOrchestrator
from vmcp.scanners.base import BaseScanner
from vmcp.utils.tool_detector import ToolDetector, MCPTool
from vmcp.utils.call_graph import build_tool_call_graphs


class ToolBasedScanOrchestrator(ScanOrchestrator):
    """Orchestrates scans and groups results by MCP tools."""

    def __init__(self, repo_path: str, org_name: str, repo_name: str):
        super().__init__(repo_path, org_name, repo_name)
        self.tools: list[MCPTool] = []
        self.tool_detector = ToolDetector(repo_path)

    async def run_all_scanners_by_tool(
        self, scanner_names: list[str] | None = None
    ) -> dict[str, dict[str, list[VulnerabilityModel]]]:
        """
        Run all scanners and group results by tool.

        Returns:
            {
                "scanner_name": {
                    "tool_name": [vulnerabilities],
                    ...
                },
                ...
            }
        """
        # First, detect tools in the repository
        self.tools = self.tool_detector.detect_tools()

        print(f"Detected {len(self.tools)} tools in repository")
        for tool in self.tools:
            print(f"  - {tool.name} ({tool.file_path})")

        # Build call graphs for each tool to track dependencies
        print("Building call graphs for tools...")
        self.tool_call_graphs = build_tool_call_graphs(self.tools, self.repo_path)
        for tool_name, dependencies in self.tool_call_graphs.items():
            print(f"  {tool_name} depends on {len(dependencies)} files")

        # Run all scanners normally
        scanner_results = await self.run_all_scanners(scanner_names)

        # Group results by tool
        tool_grouped_results: dict[str, dict[str, list[VulnerabilityModel]]] = {}

        for scanner_name, vulnerabilities in scanner_results.items():
            tool_grouped_results[scanner_name] = self._group_by_tool(vulnerabilities)

        return tool_grouped_results

    def _group_by_tool(
        self, vulnerabilities: list[VulnerabilityModel]
    ) -> dict[str, list[VulnerabilityModel]]:
        """
        Group vulnerabilities by the tool they belong to.

        Logic:
        - If vulnerability file_location is in a tool's call graph, assign to that tool
        - If vulnerability is in a dependency file, assign to 'dependencies'
        - Otherwise, assign to 'unknown'

        Uses call graph analysis to detect transitive vulnerabilities:
        - Direct file match: vuln in server.py → tool in server.py
        - Transitive match: vuln in helper.py → tool that imports helper.py
        """
        tool_vulns: dict[str, list[VulnerabilityModel]] = {}

        # Initialize with detected tools
        for tool in self.tools:
            tool_vulns[tool.name] = []

        # Special categories
        tool_vulns['dependencies'] = []
        tool_vulns['unknown'] = []

        # Dependency file patterns
        dependency_files = {
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile', 'poetry.lock',
            'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
            'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock'
        }

        for vuln in vulnerabilities:
            assigned = False

            # Check if vulnerability is in a specific tool file or its dependencies
            if vuln.file_location:
                # Normalize path - handle both absolute and relative paths
                file_path = vuln.file_location

                # If it's an absolute path, make it relative to repo_path
                if Path(file_path).is_absolute():
                    try:
                        file_path = str(Path(file_path).relative_to(self.repo_path))
                    except ValueError:
                        # Path is absolute but not under repo_path, try string replacement
                        file_path = file_path.replace(f"{self.repo_path}/", "")

                file_name = Path(file_path).name

                # Check if it's a dependency file - these go to 'dependencies' category
                if file_name in dependency_files:
                    tool_vulns['dependencies'].append(vuln)
                    assigned = True
                else:
                    # Use call graph to check if file is in any tool's dependency tree
                    # This catches both direct matches and transitive dependencies
                    for tool_name, dependencies in self.tool_call_graphs.items():
                        if file_path in dependencies:
                            tool_vulns[tool_name].append(vuln)
                            assigned = True
                            break

            # Vulnerabilities with no file location go to dependencies (usually dependency CVEs)
            if not assigned and not vuln.file_location:
                tool_vulns['dependencies'].append(vuln)
                assigned = True

            # Unknown category for everything else
            if not assigned:
                tool_vulns['unknown'].append(vuln)

        # Remove empty tool categories
        tool_vulns = {k: v for k, v in tool_vulns.items() if v}

        return tool_vulns

    def save_tool_results(
        self, results: dict[str, dict[str, list[VulnerabilityModel]]], output_dir: str
    ) -> None:
        """
        Save tool-based scan results to scanner-specific JSON files.

        Format per file: {"scanner": {"tool_name": [vulns]}}
        Filename pattern: <scanner>-tool-violations.json
        These will be merged during aggregation into org-repo-tools.json
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save scanner-specific tool results to avoid parallel overwrite
        for scanner, tool_vulns in results.items():
            formatted_tool_results: dict[str, list[dict]] = {}
            for tool_name, vulnerabilities in tool_vulns.items():
                formatted_tool_results[tool_name] = [
                    vuln.model_dump(mode='json') for vuln in vulnerabilities
                ]

            # Save to scanner-specific file
            scanner_file = output_path / f'{scanner}-tool-violations.json'
            with open(scanner_file, 'w') as f:
                json.dump({scanner: formatted_tool_results}, f, indent=2, default=str)

            print(f"Tool-based results for {scanner} saved to {scanner_file}")

        # Save tool metadata to scanner-specific file (will be merged during aggregation)
        tools_metadata_file = output_path / f'{self.org_name}-{self.repo_name}-tools-metadata.json'
        tools_data = [tool.to_dict() for tool in self.tools]
        with open(tools_metadata_file, 'w') as f:
            json.dump(tools_data, f, indent=2)

        print(f"Tool metadata saved to {tools_metadata_file}")
