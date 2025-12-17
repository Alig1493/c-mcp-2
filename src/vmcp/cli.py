"""CLI entry point for vulnerability scanner."""
import argparse
import asyncio
import sys
from pathlib import Path

import subprocess
import tempfile

from vmcp.orchestrator import ScanOrchestrator
from vmcp.utils.aggregate_results import aggregate_results, generate_summary_table, save_aggregated_results
from vmcp.utils.detect_language import detect_languages, select_scanners


def get_repo(repo_url: str):
    # Parse org/repo from URL
    if repo_url.endswith('.git'):
        repo_url = repo_url[:-4]

    parts = repo_url.rstrip('/').split('/')
    repo_name = parts[-1]
    org_name = parts[-2] if len(parts) > 1 else 'unknown'
    return org_name, repo_name


async def scan_repository(repo_url: str, output_dir: str, scanners: list[str] | None = None) -> None:
    """Scan a repository for vulnerabilities."""
    org_name, repo_name = get_repo(repo_url)    
    # Clone to temp directory
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir) / repo_name

        print(f"Cloning {repo_url}...")
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, str(repo_path)],
            check=True,
            capture_output=True
        )

        # Auto-detect scanners if not specified
        if scanners is None:
            print("Detecting repository languages...")
            languages = detect_languages(str(repo_path))
            scanners = select_scanners(languages)
            print(f"Selected scanners: {', '.join(scanners)}")

        # Run scans
        print(f"Running {len(scanners)} scanners in parallel...")
        orchestrator = ScanOrchestrator(str(repo_path), org_name, repo_name)
        results = await orchestrator.run_all_scanners(scanners)

        # Save results (scanner-specific files)
        orchestrator.save_results(results, output_dir)


def aggregate_command(repo_url: str, results_dir: str) -> None:
    """Aggregate results and generate scan results report."""
    print(f"Aggregating results from {results_dir}...")
    org_name, repo_name = get_repo(repo_url)
    results = aggregate_results(org_name, repo_name, results_dir)

    # Save aggregated results to violations.json
    save_aggregated_results(org_name, repo_name, results, results_dir)

    # Generate summary table from all repo files in results directory
    summary = generate_summary_table(results_dir)

    with open('SCAN_RESULTS.md', 'w') as f:
        f.write(summary)

    print("Generated SCAN_RESULTS.md with vulnerability summary")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='Vulnerability scanner for repositories')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a repository')
    scan_parser.add_argument('repo_url', help='Repository URL to scan')
    scan_parser.add_argument('--output-dir', default='results', help='Output directory for results')
    scan_parser.add_argument('--scanners', nargs='+', help='Specific scanners to use')

    # Aggregate command
    agg_parser = subparsers.add_parser('aggregate', help='Aggregate scan results')
    agg_parser.add_argument('repo_url', help='Repository URL to scan')
    agg_parser.add_argument('--results-dir', default='results', help='Results directory')

    args = parser.parse_args()

    if args.command == 'scan':
        asyncio.run(scan_repository(args.repo_url, args.output_dir, args.scanners))
    elif args.command == 'aggregate':
        aggregate_command(args.repo_url, args.results_dir)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
