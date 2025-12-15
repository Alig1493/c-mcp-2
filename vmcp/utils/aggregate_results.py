"""Aggregate vulnerability scan results and generate README."""
import json
import os
from collections import defaultdict
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
    """Aggregate all vulnerability results."""
    results = {}

    # Find all violations.json files
    for root, _, files in os.walk(results_dir):
        if 'violations.json' in files:
            file_path = os.path.join(root, 'violations.json')

            with open(file_path, 'r') as f:
                data = json.load(f)
                results.update(data)

    return results


def generate_summary_table(results: dict[str, Any]) -> str:
    """Generate summary table for README."""
    lines = [
        "# Vulnerability Scan Results",
        "",
        "| Project | Total Findings | Severity | Status |",
        "|---------|----------------|----------|--------|",
    ]

    for org_repo, scanners in sorted(results.items()):
        # Collect all vulnerabilities across scanners
        all_vulnerabilities = []
        for scanner, vulnerabilities in scanners.items():
            all_vulnerabilities.extend(vulnerabilities)

        total_findings = len(all_vulnerabilities)
        worst_severity = get_worst_severity(all_vulnerabilities)
        status_emoji = SEVERITY_EMOJI.get(worst_severity, '⚪')

        # Create link to results folder
        results_link = f"[{org_repo}](results/{org_repo}/violations.json)"

        lines.append(
            f"| {results_link} | {total_findings} | {worst_severity} | {status_emoji} |"
        )

    return "\n".join(lines)


def generate_detailed_report(results: dict[str, Any]) -> str:
    """Generate detailed report with per-scanner breakdown."""
    lines = [
        "",
        "## Detailed Findings",
        "",
    ]

    for org_repo, scanners in sorted(results.items()):
        lines.append(f"### {org_repo}")
        lines.append("")

        for scanner, vulnerabilities in sorted(scanners.items()):
            if vulnerabilities:
                lines.append(f"#### Scanner: {scanner}")
                lines.append(f"Found {len(vulnerabilities)} vulnerabilities")
                lines.append("")

                # Group by severity
                by_severity = defaultdict(list)
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN')
                    by_severity[severity].append(vuln)

                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'WARNING', 'NONE']:
                    if severity in by_severity:
                        lines.append(f"**{severity}**: {len(by_severity[severity])}")

                lines.append("")

    return "\n".join(lines)


def main():
    import sys

    if len(sys.argv) < 2:
        results_dir = 'results'
    else:
        results_dir = sys.argv[1]

    # Aggregate results
    results = aggregate_results(results_dir)

    # Generate report (summary only, no details)
    summary = generate_summary_table(results)

    # Write to SCAN_RESULTS.md (not README.md)
    with open('SCAN_RESULTS.md', 'w') as f:
        f.write(summary)

    print("Generated SCAN_RESULTS.md with vulnerability summary")


if __name__ == '__main__':
    main()
