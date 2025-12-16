"""Aggregate vulnerability scan results and generate README."""
import json
import os
from pathlib import Path
from typing import Any


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


def aggregate_results(results_dir: str) -> dict[str, Any]:
    """Aggregate all vulnerability results from scanner-specific and existing violations files."""
    aggregated = {}
    results_path = Path(results_dir)

    # Find all violations files (both scanner-specific and existing violations.json)
    scanner_files = list(results_path.glob('**/*-violations.json'))  # e.g., trivy-violations.json
    existing_files = list(results_path.glob('**/violations.json'))   # existing aggregated files

    all_files = scanner_files + existing_files

    for violations_file in all_files:
        with open(violations_file, 'r') as f:
            data = json.load(f)

            # Merge scanner results for each repo
            for org_repo, scanner_results in data.items():
                if org_repo not in aggregated:
                    aggregated[org_repo] = {}

                # Merge scanner findings
                for scanner_name, vulnerabilities in scanner_results.items():
                    # Don't overwrite existing scanner data unless it's empty
                    if scanner_name not in aggregated[org_repo]:
                        aggregated[org_repo][scanner_name] = vulnerabilities
                    elif not aggregated[org_repo][scanner_name] and vulnerabilities:
                        # Replace empty data with non-empty data
                        aggregated[org_repo][scanner_name] = vulnerabilities

    return aggregated


def save_aggregated_results(results: dict[str, Any], results_dir: str) -> None:
    """Save aggregated results to a single violations.json file for each repo."""
    results_path = Path(results_dir)

    for org_repo, scanner_results in results.items():
        # Create output directory for this repo
        output_dir = results_path / org_repo.replace('/', os.sep)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save aggregated results
        violations_file = output_dir / 'violations.json'
        aggregated_data = {org_repo: scanner_results}

        with open(violations_file, 'w') as f:
            json.dump(aggregated_data, f, indent=2, default=str)

        print(f"Aggregated results saved to {violations_file}")

        # Remove scanner-specific files after aggregation
        scanner_files = list(output_dir.glob('*-violations.json'))
        for scanner_file in scanner_files:
            scanner_file.unlink()
            print(f"Removed scanner-specific file: {scanner_file}")


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
    lines = [
        "# Vulnerability Scan Results",
        "",
        "| Project | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |",
        "|---------|-------|----------|------|--------|-----|---------|----------|--------|",
    ]

    for org_repo, scanners in sorted(results.items()):
        # Collect all vulnerabilities across scanners
        all_vulnerabilities = []
        for scanner, vulnerabilities in scanners.items():
            all_vulnerabilities.extend(vulnerabilities)

        total_findings = len(all_vulnerabilities)
        worst_severity = get_worst_severity(all_vulnerabilities)
        status_emoji = SEVERITY_EMOJI.get(worst_severity, '⚪')

        # Get severity breakdown
        severity_counts = count_by_severity(all_vulnerabilities)

        # Count fixable vulnerabilities
        fixable_count = count_fixable(all_vulnerabilities)

        # Get scanners used
        scanners_used = get_scanners_used(scanners)

        # Create link to results folder
        results_link = f"[{org_repo}](results/{org_repo}/violations.json)"

        lines.append(
            f"| {results_link} | {total_findings} | "
            f"{severity_counts['CRITICAL']} | {severity_counts['HIGH']} | "
            f"{severity_counts['MEDIUM']} | {severity_counts['LOW']} | "
            f"{fixable_count} | {scanners_used} | {status_emoji} |"
        )

    return "\n".join(lines)


def main():
    import sys

    if len(sys.argv) < 2:
        results_dir = 'results'
    else:
        results_dir = sys.argv[1]

    # Aggregate results
    results = aggregate_results(results_dir)

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
