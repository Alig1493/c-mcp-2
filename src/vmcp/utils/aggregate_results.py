"""Aggregate vulnerability scan results and generate README."""
import json
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

TEMP_SCANNER_FILE_NAMES = [f"{scanner}-violations.json" for scanner in SCANNER_MAP]


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
    """
    Aggregate scanner results for a specific repository.

    New format: {"scanner_name": [vulns]}
    """
    aggregated = {}
    results_path = Path(results_dir)

    # Load existing per-repo file in new format: org-repo-violations.json
    per_repo_file = results_path / f'{org_name}-{repo_name}-violations.json'
    if per_repo_file.exists():
        with open(per_repo_file, 'r') as f:
            aggregated = json.load(f)

    # Load scanner-specific temporary files from new scans
    for scanner_name in SCANNER_MAP.keys():
        scanner_file = results_path / f'{scanner_name}-violations.json'
        if scanner_file.exists():
            with open(scanner_file, 'r') as f:
                scanner_data = json.load(f)
                # Merge scanner results
                for scanner, vulns in scanner_data.items():
                    aggregated[scanner] = vulns

    return aggregated


def save_aggregated_results(org_name: str, repo_name: str, results: dict[str, Any], results_dir: str) -> None:
    """
    Save aggregated results to per-repo violations.json file.

    New format: {"scanner_name": [vulns]}
    """
    results_path = Path(results_dir)
    results_path.mkdir(parents=True, exist_ok=True)

    # Save to org-repo-violations.json
    violations_file = results_path / f'{org_name}-{repo_name}-violations.json'
    with open(violations_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"Saved results to {violations_file}")

    # Remove scanner-specific temporary files
    for scanner_name in SCANNER_MAP.keys():
        temp_file = results_path / f'{scanner_name}-violations.json'
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
    scanner_names = sorted(scanners.keys())
    return ', '.join(scanner_names) if scanner_names else 'None'


def generate_summary_table(results_dir: str) -> str:
    """Generate summary table for README by iterating through all violations files."""
    rows = []
    results_path = Path(results_dir)

    # Iterate through all org-repo-violations.json files
    for json_file in results_path.glob('*-*-violations.json'):
        # Skip temp scanner files
        if json_file.name in TEMP_SCANNER_FILE_NAMES:
            continue

        # Extract org/repo from filename: org-repo-violations.json -> org/repo
        filename_parts = json_file.stem.replace('-violations', '').split('-', 1)
        if len(filename_parts) != 2:
            continue

        org_name, repo_name = filename_parts
        org_repo = f"{org_name}/{repo_name}"

        # Load scanner results (new format: {"scanner": [vulns]})
        with open(json_file, 'r') as f:
            scanners = json.load(f)

        # Collect all vulnerabilities across scanners
        all_vulnerabilities = []
        for scanner_vulns in scanners.values():
            all_vulnerabilities.extend(scanner_vulns)

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
            'filename': f'{org_name}-{repo_name}-violations.json',
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
        # Link to original GitHub repository
        repo_link = f"[{row['org_repo']}](https://github.com/{row['org_repo']})"

        # Link to violations file
        violations_link = f"[📋](results/{row['filename']})"

        lines.append(
            f"| {repo_link} | {violations_link} | {row['total']} | "
            f"{row['severity_counts']['CRITICAL']} | {row['severity_counts']['HIGH']} | "
            f"{row['severity_counts']['MEDIUM']} | {row['severity_counts']['LOW']} | "
            f"{row['fixable']} | {row['scanners']} | {row['status']} |"
        )

    return "\n".join(lines)


def main():
    import sys

    if len(sys.argv) < 4:
        print("Usage: aggregate_results.py <org_name> <repo_name> <results_dir>")
        sys.exit(1)

    org_name = sys.argv[1]
    repo_name = sys.argv[2]
    results_dir = sys.argv[3]

    # Aggregate results for this specific repo
    results = aggregate_results(org_name, repo_name, results_dir)

    # Save aggregated results
    save_aggregated_results(org_name, repo_name, results, results_dir)

    # Generate full summary table from all repo files
    summary = generate_summary_table(results_dir)

    # Write to SCAN_RESULTS.md
    with open('SCAN_RESULTS.md', 'w') as f:
        f.write(summary)

    print("Generated SCAN_RESULTS.md with vulnerability summary")


if __name__ == '__main__':
    main()
