"""Utility modules for VMCP."""
from vmcp.utils.aggregate_results import (
    aggregate_results,
    generate_detailed_report,
    generate_summary_table,
    get_worst_severity,
)
from vmcp.utils.detect_language import (
    check_dependencies,
    detect_languages,
    select_scanners,
)
from vmcp.utils.enhance_cve_links import (
    enhance_vulnerabilities,
    process_results_file,
)

__all__ = [
    "aggregate_results",
    "generate_detailed_report",
    "generate_summary_table",
    "get_worst_severity",
    "check_dependencies",
    "detect_languages",
    "select_scanners",
    "enhance_vulnerabilities",
    "process_results_file",
]
