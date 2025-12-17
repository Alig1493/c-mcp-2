"""Tests for scanner orchestration."""
import tempfile
from pathlib import Path

import pytest

from vmcp.orchestrator import ScanOrchestrator


def test_orchestrator_initialization():
    """Test ScanOrchestrator initialization."""
    orchestrator = ScanOrchestrator("/tmp/test", "org", "repo")
    assert orchestrator.repo_path == "/tmp/test"
    assert orchestrator.org_name == "org"
    assert orchestrator.repo_name == "repo"


def test_scanner_map_exists():
    """Test that scanner map is defined."""
    assert len(ScanOrchestrator.SCANNER_MAP) > 0
    assert 'trivy' in ScanOrchestrator.SCANNER_MAP
    assert 'osv-scanner' in ScanOrchestrator.SCANNER_MAP
    assert 'semgrep' in ScanOrchestrator.SCANNER_MAP
    assert 'yara' in ScanOrchestrator.SCANNER_MAP


def test_save_results():
    """Test saving results to JSON file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        orchestrator = ScanOrchestrator("/tmp/test", "testorg", "testrepo")

        # Create fake results
        results = {
            'trivy': [],
            'osv-scanner': []
        }

        orchestrator.save_results(results, temp_dir)

        # Check scanner files were created (per-scanner format)
        trivy_file = Path(temp_dir) / 'trivy-violations.json'
        osv_file = Path(temp_dir) / 'osv-scanner-violations.json'

        assert trivy_file.exists()
        assert osv_file.exists()

        # Check content
        import json
        with open(trivy_file) as f:
            trivy_data = json.load(f)

        assert 'testorg/testrepo' in trivy_data
        assert 'trivy' in trivy_data['testorg/testrepo']
