"""Aggregate tool-based vulnerability scan results and generate SCAN_RESULTS_TOOLS.md."""
import json
from pathlib import Path
from typing import Any

from vmcp.utils.aggregate_results import (
    SEVERITY_ORDER,
    SEVERITY_EMOJI,
    get_worst_severity,
    count_by_severity,
    count_fixable,
)


def aggregate_tool_results(org_name: str, repo_name: str, results_dir: str) -> dict[str, Any]:
    """
    Aggregate tool-based scanner results for a specific repository.

    Format: {"scanner": {"tool_name": [vulns]}}
    """
    results_path = Path(results_dir)

    # Load existing per-repo tool-violations file
    per_repo_file = results_path / f'{org_name}-{repo_name}-tool-violations.json'

    if per_repo_file.exists():
        with open(per_repo_file, 'r') as f:
            return json.load(f)

    return {}


def save_tool_results(
    org_name: str, repo_name: str, results: dict[str, Any], results_dir: str
) -> None:
    """
    Save aggregated tool-based results to per-repo tool-violations.json file.

    Format: {"scanner": {"tool_name": [vulns]}}
    """
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    # Save to org-repo-tool-violations.json
    violations_file = results_path / f'{org_name}-{repo_name}-tool-violations.json'
    with open(violations_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Saved tool-based results to {violations_file}")


def generate_tool_summary_table(results_dir: str) -> str:
    """
    Generate summary table for SCAN_RESULTS_TOOLS.md.

    Table shows vulnerabilities per tool across all repositories.
    """
    rows = []
    results_path = Path(results_dir)

    # Iterate through all org-repo-tool-violations.json files
    for json_file in results_path.glob('*-*-tool-violations.json'):
        # Extract org/repo from filename
        filename_parts = json_file.stem.replace('-tool-violations', '').split('-', 1)
        if len(filename_parts) != 2:
            continue

        org_name, repo_name = filename_parts
        org_repo = f"{org_name}/{repo_name}"

        # Load tool-based scanner results
        with open(json_file, 'r') as f:
            scanner_results = json.load(f)

        # Load tool metadata if available
        tools_metadata_file = results_path / f'{org_name}-{repo_name}-tools.json'
        tool_descriptions = {}
        if tools_metadata_file.exists():
            with open(tools_metadata_file, 'r') as f:
                tools_data = json.load(f)
                tool_descriptions = {tool['name']: tool.get('description', '') for tool in tools_data}

        # Collect all tools across all scanners
        all_tools = set()
        for scanner_tools in scanner_results.values():
            all_tools.update(scanner_tools.keys())

        # Create a row for each tool
        for tool_name in sorted(all_tools):
            # Collect all vulnerabilities for this tool across all scanners
            tool_vulnerabilities = []
            scanners_used = []

            for scanner_name, tool_vulns in scanner_results.items():
                if tool_name in tool_vulns:
                    tool_vulnerabilities.extend(tool_vulns[tool_name])
                    if tool_vulns[tool_name]:  # Only add scanner if it found vulns
                        scanners_used.append(scanner_name)

            if not tool_vulnerabilities:
                continue  # Skip tools with no vulnerabilities

            total_findings = len(tool_vulnerabilities)
            worst_severity = get_worst_severity(tool_vulnerabilities)
            severity_priority = SEVERITY_ORDER.get(worst_severity, 999)
            status_emoji = SEVERITY_EMOJI.get(worst_severity, '⚪')

            # Get severity breakdown
            severity_counts = count_by_severity(tool_vulnerabilities)

            # Count fixable vulnerabilities
            fixable_count = count_fixable(tool_vulnerabilities)

            # Get scanners used
            scanners_str = ', '.join(sorted(scanners_used)) if scanners_used else 'None'

            # Get tool description
            tool_desc = tool_descriptions.get(tool_name, '')

            # Store row data with sort key
            rows.append({
                'org_repo': org_repo,
                'tool_name': tool_name,
                'tool_desc': tool_desc[:50] + '...' if len(tool_desc) > 50 else tool_desc,
                'filename': f'{org_name}-{repo_name}-tool-violations.json',
                'total': total_findings,
                'severity_counts': severity_counts,
                'fixable': fixable_count,
                'scanners': scanners_str,
                'status': status_emoji,
                'sort_key': (-severity_priority, org_repo, tool_name),  # Worst first, then alphabetical
            })

    # Sort rows by severity (worst first), then by repo, then by tool
    rows.sort(key=lambda r: r['sort_key'])

    # Generate table lines
    lines = [
        "# Vulnerability Scan Results by Tool",
        "",
        "This report shows vulnerabilities grouped by MCP tools.",
        "",
        "| Project | Tool | Description | Results | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |",
        "|---------|------|-------------|---------|-------|----------|------|--------|-----|---------|----------|--------|",
    ]

    for row in rows:
        # Link to original GitHub repository
        repo_link = f"[{row['org_repo']}](https://github.com/{row['org_repo']})"

        # Link to tool violations file
        violations_link = f"[📋](results/{row['filename']})"

        # Tool name with special formatting for special categories
        tool_display = row['tool_name']
        if tool_display == 'dependencies':
            tool_display = '📦 dependencies'
        elif tool_display == 'unknown':
            tool_display = '❓ unknown'

        lines.append(
            f"| {repo_link} | {tool_display} | {row['tool_desc']} | {violations_link} | {row['total']} | "
            f"{row['severity_counts']['CRITICAL']} | {row['severity_counts']['HIGH']} | "
            f"{row['severity_counts']['MEDIUM']} | {row['severity_counts']['LOW']} | "
            f"{row['fixable']} | {row['scanners']} | {row['status']} |"
        )

    return "\n".join(lines)


def main():
    import sys

    if len(sys.argv) < 4:
        print("Usage: aggregate_tool_results.py <org_name> <repo_name> <results_dir>")
        sys.exit(1)

    org_name = sys.argv[1]
    repo_name = sys.argv[2]
    results_dir = sys.argv[3]

    # Aggregate results for this specific repo
    results = aggregate_tool_results(org_name, repo_name, results_dir)

    # Save aggregated results
    save_tool_results(org_name, repo_name, results, results_dir)

    # Generate full summary table from all repo files
    summary = generate_tool_summary_table(results_dir)

    # Write to SCAN_RESULTS_TOOLS.md
    with open('SCAN_RESULTS_TOOLS.md', 'w') as f:
        f.write(summary)

    print("Generated SCAN_RESULTS_TOOLS.md with tool-based vulnerability summary")


if __name__ == '__main__':
    main()
