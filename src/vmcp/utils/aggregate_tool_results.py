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


def aggregate_tool_results(org_name: str, repo_name: str, results_dir: str) -> list[dict[str, Any]]:
    """
    Aggregate tool-based scanner results for a specific repository.

    Merges scanner-specific *-tool-violations.json files into a single tools file.
    Format: [
        {
            "name": "tool_name",
            "file_path": "path/to/tool.py",
            "description": "Tool description",
            "line_number": 75,
            "language": "python",
            "scanner1": [vulns],
            "scanner2": [vulns],
            ...
        }
    ]
    """
    results_path = Path(results_dir)

    # Load tool metadata
    metadata_file = results_path / f'{org_name}-{repo_name}-tools-metadata.json'
    if not metadata_file.exists():
        print(f"No tool metadata found at {metadata_file}")
        return []

    with open(metadata_file, 'r') as f:
        tools_metadata = json.load(f)

    # Find all scanner-specific tool-violations files
    scanner_files = list(results_path.glob('*-tool-violations.json'))

    if not scanner_files:
        print(f"No scanner-specific tool-violations files found in {results_dir}")
        return []

    # Build tool-based aggregation
    tools_dict: dict[str, dict[str, Any]] = {}

    # Initialize with metadata
    for tool in tools_metadata:
        tool_name = tool['name']
        tools_dict[tool_name] = {
            'name': tool_name,
            'file_path': tool['file_path'],
            'description': tool.get('description', ''),
            'line_number': tool.get('line_number'),
            'language': tool.get('language', 'unknown')
        }

    # Add special categories
    tools_dict['dependencies'] = {
        'name': 'dependencies',
        'file_path': '',
        'description': 'Project dependencies',
        'line_number': None,
        'language': 'N/A'
    }
    tools_dict['unknown'] = {
        'name': 'unknown',
        'file_path': '',
        'description': 'Unclassified vulnerabilities',
        'line_number': None,
        'language': 'N/A'
    }

    # Merge scanner results into tools
    for scanner_file in scanner_files:
        try:
            with open(scanner_file, 'r') as f:
                scanner_data = json.load(f)

            # Each file contains {"scanner_name": {"tool_name": [vulns]}}
            for scanner_name, tool_results in scanner_data.items():
                for tool_name, vulns in tool_results.items():
                    if tool_name in tools_dict:
                        tools_dict[tool_name][scanner_name] = vulns
                    else:
                        # Tool not in metadata, add as unknown
                        if tool_name not in tools_dict:
                            tools_dict[tool_name] = {
                                'name': tool_name,
                                'file_path': '',
                                'description': '',
                                'line_number': None,
                                'language': 'unknown'
                            }
                        tools_dict[tool_name][scanner_name] = vulns

            print(f"Merged {scanner_file.name}")

        except Exception as e:
            print(f"Error reading {scanner_file}: {e}")
            continue

    # Remove empty tools (no scanner results)
    tools_list = []
    for tool_name, tool_data in tools_dict.items():
        # Check if tool has any scanner results
        has_results = any(k for k in tool_data.keys() if k not in ['name', 'file_path', 'description', 'line_number', 'language'])
        if has_results:
            tools_list.append(tool_data)

    return tools_list


def save_tool_results(
    org_name: str, repo_name: str, results: list[dict[str, Any]], results_dir: str
) -> None:
    """
    Save aggregated tool-based results to per-repo tools.json file.

    Format: [{"name": "tool", "file_path": "...", "scanner1": [vulns], ...}]
    """
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    # Save to org-repo-tools.json
    tools_file = results_path / f'{org_name}-{repo_name}-tools.json'
    with open(tools_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Saved tool-based results to {tools_file}")

    # Clean up scanner-specific files
    scanner_files = list(results_path.glob('*-tool-violations.json'))
    metadata_file = results_path / f'{org_name}-{repo_name}-tools-metadata.json'

    for file in scanner_files:
        file.unlink()
        print(f"Deleted {file.name}")

    if metadata_file.exists():
        metadata_file.unlink()
        print(f"Deleted {metadata_file.name}")


def generate_tool_summary_table(results_dir: str) -> str:
    """
    Generate summary table for SCAN_RESULTS_TOOLS.md.

    One row per repository showing all tools scanned.
    """
    rows = []
    results_path = Path(results_dir)

    # Iterate through all org-repo-tools.json files
    for json_file in results_path.glob('*-*-tools.json'):
        # Extract org/repo from filename
        filename_parts = json_file.stem.replace('-tools', '').split('-', 1)
        if len(filename_parts) != 2:
            continue

        org_name, repo_name = filename_parts
        org_repo = f"{org_name}/{repo_name}"

        # Load tool-based results
        with open(json_file, 'r') as f:
            tools_data = json.load(f)

        # Separate actual MCP tools from virtual categories
        actual_tools = []
        dependencies_entry = None
        unknown_entry = None

        for tool in tools_data:
            if tool['name'] == 'dependencies':
                dependencies_entry = tool
            elif tool['name'] == 'unknown':
                unknown_entry = tool
            else:
                # Actual MCP tool
                actual_tools.append(tool)

        # Collect all vulnerabilities across all categories
        all_vulnerabilities = []
        all_scanners = set()

        for tool in tools_data:
            # Get all scanner keys (exclude metadata fields)
            scanner_keys = [k for k in tool.keys() if k not in ['name', 'file_path', 'description', 'line_number', 'language']]
            all_scanners.update(scanner_keys)

            for scanner_key in scanner_keys:
                all_vulnerabilities.extend(tool[scanner_key])

        if not all_vulnerabilities:
            continue  # Skip repos with no vulnerabilities

        total_findings = len(all_vulnerabilities)
        worst_severity = get_worst_severity(all_vulnerabilities)
        severity_priority = SEVERITY_ORDER.get(worst_severity, 999)
        status_emoji = SEVERITY_EMOJI.get(worst_severity, '⚪')

        # Get severity breakdown
        severity_counts = count_by_severity(all_vulnerabilities)

        # Count fixable vulnerabilities
        fixable_count = count_fixable(all_vulnerabilities)

        # Format scanners list
        scanners_str = ', '.join(sorted(all_scanners)) if all_scanners else 'None'

        # Format actual tools list (not including dependencies/unknown)
        tool_names = [t['name'] for t in actual_tools]
        if tool_names:
            tools_str = ', '.join(tool_names[:3])  # Show first 3 tools
            if len(tool_names) > 3:
                tools_str += f' (+{len(tool_names) - 3} more)'
        else:
            tools_str = '—'  # No actual tools detected

        # Count vulnerabilities in dependencies
        deps_count = 0
        if dependencies_entry:
            for scanner_key in [k for k in dependencies_entry.keys() if k not in ['name', 'file_path', 'description', 'line_number', 'language']]:
                deps_count += len(dependencies_entry[scanner_key])

        # Count vulnerabilities in unknown
        unknown_count = 0
        if unknown_entry:
            for scanner_key in [k for k in unknown_entry.keys() if k not in ['name', 'file_path', 'description', 'line_number', 'language']]:
                unknown_count += len(unknown_entry[scanner_key])

        # Store row data with sort key
        rows.append({
            'org_repo': org_repo,
            'tools': tools_str,
            'tool_count': len(actual_tools),  # Only count actual tools
            'deps_count': deps_count,
            'unknown_count': unknown_count,
            'filename': f'{org_name}-{repo_name}-tools.json',
            'total': total_findings,
            'severity_counts': severity_counts,
            'fixable': fixable_count,
            'scanners': scanners_str,
            'status': status_emoji,
            'sort_key': (-severity_priority, -total_findings, org_repo),  # Worst first, then by count
        })

    # Sort rows by severity (worst first), then by total vulnerabilities
    rows.sort(key=lambda r: r['sort_key'])

    # Generate table lines
    lines = [
        "# Vulnerability Scan Results by Tool",
        "",
        "This report shows vulnerabilities grouped by MCP tools.",
        "",
        "| Project | MCP Tools | Results | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |",
        "|---------|-----------|---------|-------|----------|------|--------|-----|---------|----------|--------|",
    ]

    for row in rows:
        # Link to original GitHub repository
        repo_link = f"[{row['org_repo']}](https://github.com/{row['org_repo']})"

        # Link to results file
        results_link = f"[📋 View](results_tools/{row['filename']})"

        lines.append(
            f"| {repo_link} | {row['tools']} | {results_link} | {row['total']} | "
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
