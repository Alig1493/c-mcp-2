"""Aggregate vulnerability scan results and generate README."""
import json
import os
from pathlib import Path
from typing import Any

from vmcp.orchestrator import SCANNER_MAP


SEVERITY_ORDER = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'UNKNOWN': 4,
    'WARNING': 5,
    'NONE': 6,
}

SEVERITY_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH': '🔴',
    'MEDIUM': '🟡',
    'LOW': '🟡',
    'UNKNOWN': '🟡',
    'WARNING': '🟡',
    'NONE': '🟢',
}

TEMP_SCANNER_FILE_NAMES = [
    f"{scanner}-violations.json"
    for scanner in SCANNER_MAP
]


def get_worst_severity(vulnerabilities: list[dict[str, Any]]) -> str:
    """Get the worst (highest priority) severity from a list of findings."""
    if not vulnerabilities:
        return 'NONE'

    worst_severity = 'NONE'
    worst_priority = SEVERITY_ORDER.get(worst_severity, 999)

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'UNKNOWN')
        priority = SEVERITY_ORDER.get(severity, 999)

        if priority < worst_priority:
            worst_severity = severity
            worst_priority = priority

    return worst_severity


def aggregate_results(org_name: str, repo_name: str, results_dir: str) -> dict[str, Any]:
    """Aggregate all vulnerability results from per-repo and scanner-specific files."""
    aggregated = {}
    results_path = Path(results_dir)

    # Find all violations.json files in the results directory
    # This includes:
    # 1. Per-repo files: <org>-<repo>-violations.json (new format)

    # Load existing per-repo files in new format: <org>-<repo>-violations.json
    per_repo_files = list(results_path.glob(f'{org_name}-{repo_name}-violations.json'))
    for per_repo_file in per_repo_files:
        # Skip scanner-specific temp files
        if not per_repo_file.name in TEMP_SCANNER_FILE_NAMES:
            with open(per_repo_file, 'r') as f:
                data = json.load(f)
                for org_repo, scanner_results in data.items():
                    if org_repo not in aggregated:
                        aggregated[org_repo] = {}
                    for scanner_name, vulnerabilities in scanner_results.items():
                        aggregated[org_repo][scanner_name] = vulnerabilities

    # Load scanner-specific temporary files from new scans
    temp_scanner_files = [
        results_path / temp_scanner_file_name 
        for temp_scanner_file_name in TEMP_SCANNER_FILE_NAMES 
    ]
    for scanner_file in temp_scanner_files:
        if scanner_file.exists():
            with open(scanner_file, 'r') as f:
                data = json.load(f)
                for org_repo, scanner_results in data.items():
                    if org_repo not in aggregated:
                        aggregated[org_repo] = {}
                    for scanner_name, vulnerabilities in scanner_results.items():
                        aggregated[org_repo][scanner_name] = vulnerabilities

    return aggregated


def save_aggregated_results(org_name: str, repo_name: str, results: dict[str, Any], results_dir: str) -> None:
    """Save aggregated results to per-repo violations.json files."""
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)
    org_repo = f"{org_name}/{repo_name}"

    # Convert org/repo to org-repo format for filename
    violations_file = results_path / f'{org_name}-{repo_name}-violations.json'

    # Save only this repo's data
    repo_data = {org_repo: results[org_repo]}

    with open(violations_file, 'w') as f:
        json.dump(repo_data, f, indent=2, default=str)

    print(f"Saved results to {violations_file}")

    # Remove scanner-specific temporary files (trivy-violations.json, osv-scanner-violations.json, etc.)
    # These are from individual scanner runs, not the final per-repo files
    temp_scanner_files = [
        results_path / temp_scanner_file_name 
        for temp_scanner_file_name in TEMP_SCANNER_FILE_NAMES 
    ]
    for temp_file in temp_scanner_files:
        if temp_file.exists():
            temp_file.unlink()
            print(f"Removed temporary scanner file: {temp_file}")


def count_by_severity(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    """Count vulnerabilities by severity."""
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'UNKNOWN')
        if severity in counts:
            counts[severity] += 1
    return counts


def count_fixable(vulnerabilities: list[dict[str, Any]]) -> int:
    """Count vulnerabilities with available fixes."""
    return sum(1 for vuln in vulnerabilities if vuln.get('fixed_version'))


def get_scanners_used(scanners: dict[str, list]) -> str:
    """Get list of scanners that were used."""
    scanner_names = []
    for scanner_name, vulns in scanners.items():
        # Only include scanners that actually ran (even if no vulns found)
        scanner_names.append(scanner_name)
    return ', '.join(sorted(scanner_names)) if scanner_names else 'None'


def generate_summary_table(results: dict[str, Any]) -> str:
    """Generate summary table for README."""
    # Prepare all row data first
    rows = []
    print(results)

    for org_repo, scanners in results.items():
        # Collect all vulnerabilities across scanners (done once)
        all_vulnerabilities = []
        for scanner, vulnerabilities in scanners.items():
            all_vulnerabilities.extend(vulnerabilities)

        total_findings = len(all_vulnerabilities)
        worst_severity = get_worst_severity(all_vulnerabilities)
        severity_priority = SEVERITY_ORDER.get(worst_severity, 999)
        status_emoji = SEVERITY_EMOJI.get(worst_severity, '⚪')

        # Get severity breakdown
        severity_counts = count_by_severity(all_vulnerabilities)

        # Count fixable vulnerabilities
        fixable_count = count_fixable(all_vulnerabilities)

        # Get scanners used
        scanners_used = get_scanners_used(scanners)

        # Store row data with sort key
        rows.append({
            'org_repo': org_repo,
            'total': total_findings,
            'severity_counts': severity_counts,
            'fixable': fixable_count,
            'scanners': scanners_used,
            'status': status_emoji,
            'sort_key': (-severity_priority, org_repo)  # Best first, then alphabetical
        })

    # Sort rows by severity (best first), then by name
    rows.sort(key=lambda r: r['sort_key'])

    # Generate table lines
    lines = [
        "# Vulnerability Scan Results",
        "",
        "| Project | Results | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |",
        "|---------|---------|-------|----------|------|--------|-----|---------|----------|--------|",
    ]

    for row in rows:
        # Convert org/repo to org-repo for filename
        safe_filename = row['org_repo'].replace('/', '-')

        # Link to original GitHub repository
        repo_link = f"[{row['org_repo']}](https://github.com/{row['org_repo']})"

        # Link to violations file
        violations_link = f"[📋](results/{safe_filename}-violations.json)"

        lines.append(
            f"| {repo_link} | {violations_link} | {row['total']} | "
            f"{row['severity_counts']['CRITICAL']} | {row['severity_counts']['HIGH']} | "
            f"{row['severity_counts']['MEDIUM']} | {row['severity_counts']['LOW']} | "
            f"{row['fixable']} | {row['scanners']} | {row['status']} |"
        )

    return "\n".join(lines)


def main():
    import sys

    org_name = sys.argv[1]
    repo_name = sys.argv[2]
    results_dir = sys.argv[3]

    # Aggregate results
    results = aggregate_results(org_name, repo_name, results_dir)

    # Save aggregated results to violations.json
    save_aggregated_results(results, results_dir)

    # Generate report (summary only, no details)
    summary = generate_summary_table(results)

    # Write to SCAN_RESULTS.md (not README.md)
    with open('SCAN_RESULTS.md', 'w') as f:
        f.write(summary)

    print("Generated SCAN_RESULTS.md with vulnerability summary")


if __name__ == '__main__':
    main()
