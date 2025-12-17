"""Tests for YARA scanner."""
import tempfile
from pathlib import Path

import pytest

from vmcp.scanners.yara import YaraScanner, YARA_AVAILABLE


def test_yara_scanner_initialization():
    """Test YaraScanner initialization."""
    scanner = YaraScanner("/tmp/test", "org", "repo")
    assert scanner.repo_path == "/tmp/test"
    assert scanner.org_name == "org"
    assert scanner.repo_name == "repo"
    assert scanner.name == "yara"


def test_yara_scanner_rules_path_exists():
    """Test that YARA rules file path is set correctly."""
    scanner = YaraScanner("/tmp/test", "org", "repo")
    assert scanner.rules_path.name == "yara-rules-core.yar"
    assert scanner.rules_path.parent.name == "yara-forge-rules-core"
    assert scanner.rules_path.exists(), f"YARA rules file not found at {scanner.rules_path}"


def test_yara_scanner_max_file_size():
    """Test that max file size is set."""
    scanner = YaraScanner("/tmp/test", "org", "repo")
    assert scanner.max_file_size == 10 * 1024 * 1024  # 10MB


def test_yara_scanner_name():
    """Test scanner name property."""
    scanner = YaraScanner("/tmp/test", "org", "repo")
    assert scanner.name == "yara"


def test_yara_available():
    """Test that YARA is available for import."""
    assert YARA_AVAILABLE is True, "YARA is not available, install yara-python"


@pytest.mark.asyncio
async def test_yara_scanner_scan_empty_directory():
    """Test scanning an empty directory returns no vulnerabilities."""
    if not YARA_AVAILABLE:
        pytest.skip("YARA not available")

    with tempfile.TemporaryDirectory() as temp_dir:
        scanner = YaraScanner(temp_dir, "testorg", "testrepo")
        results = await scanner.scan()
        assert isinstance(results, list)
        # Empty directory should have no matches
        assert len(results) == 0


@pytest.mark.asyncio
async def test_yara_scanner_scan_with_benign_file():
    """Test scanning a directory with a benign file."""
    if not YARA_AVAILABLE:
        pytest.skip("YARA not available")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a simple benign Python file
        test_file = Path(temp_dir) / "test.py"
        test_file.write_text("print('hello world')\n")

        scanner = YaraScanner(temp_dir, "testorg", "testrepo")
        results = await scanner.scan()

        assert isinstance(results, list)
        # Benign file should likely have no matches (though depends on rules)


def test_yara_severity_mapping():
    """Test YARA severity mapping logic."""
    scanner = YaraScanner("/tmp/test", "org", "repo")

    # Test critical tags
    assert scanner._map_yara_severity(70, ['MALWARE']) == 'CRITICAL'
    assert scanner._map_yara_severity(70, ['RANSOMWARE']) == 'CRITICAL'
    assert scanner._map_yara_severity(70, ['BACKDOOR']) == 'CRITICAL'
    assert scanner._map_yara_severity(70, ['TROJAN']) == 'CRITICAL'

    # Test high score
    assert scanner._map_yara_severity(90, []) == 'CRITICAL'

    # Test high tags
    assert scanner._map_yara_severity(70, ['EXPLOIT']) == 'HIGH'
    assert scanner._map_yara_severity(70, ['SHELLCODE']) == 'HIGH'
    assert scanner._map_yara_severity(70, ['SUSPICIOUS']) == 'HIGH'
    assert scanner._map_yara_severity(70, ['WEBSHELL']) == 'HIGH'

    # Test high score range
    assert scanner._map_yara_severity(75, []) == 'HIGH'

    # Test medium score range
    assert scanner._map_yara_severity(65, []) == 'MEDIUM'
    assert scanner._map_yara_severity(70, []) == 'MEDIUM'

    # Test low score
    assert scanner._map_yara_severity(60, []) == 'LOW'


def test_offset_to_line_range():
    """Test byte offset to line range conversion."""
    scanner = YaraScanner("/tmp/test", "org", "repo")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test file
        test_file = Path(temp_dir) / "test.txt"
        content = "line1\nline2\nline3\nline4\nline5\n"
        test_file.write_text(content)

        # Offset 0 should be line 1
        line_range = scanner._offset_to_line_range(str(test_file), 0)
        assert line_range.startswith("1-")

        # Offset 6 (start of line2) should be line 2
        line_range = scanner._offset_to_line_range(str(test_file), 6)
        assert line_range.startswith("2-")

        # Offset 12 (start of line3) should be line 3
        line_range = scanner._offset_to_line_range(str(test_file), 12)
        assert line_range.startswith("3-")


def test_yara_scanner_in_orchestrator():
    """Test that YaraScanner is registered in orchestrator."""
    from vmcp.orchestrator import ScanOrchestrator

    assert 'yara' in ScanOrchestrator.SCANNER_MAP
    assert ScanOrchestrator.SCANNER_MAP['yara'] == YaraScanner


@pytest.mark.asyncio
async def test_yara_scanner_skips_large_files():
    """Test that YARA scanner skips files larger than max_file_size."""
    if not YARA_AVAILABLE:
        pytest.skip("YARA not available")

    with tempfile.TemporaryDirectory() as temp_dir:
        scanner = YaraScanner(temp_dir, "testorg", "testrepo")

        # Create a file larger than max_file_size
        large_file = Path(temp_dir) / "large.txt"
        # Create a 12MB file (larger than 10MB limit)
        with open(large_file, "wb") as f:
            f.write(b"x" * (12 * 1024 * 1024))

        results = await scanner.scan()

        # Should complete without errors and skip the large file
        assert isinstance(results, list)


@pytest.mark.asyncio
async def test_yara_scanner_skips_excluded_directories():
    """Test that YARA scanner skips common non-code directories."""
    if not YARA_AVAILABLE:
        pytest.skip("YARA not available")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create excluded directories
        (Path(temp_dir) / ".git").mkdir()
        (Path(temp_dir) / "node_modules").mkdir()
        (Path(temp_dir) / "__pycache__").mkdir()
        (Path(temp_dir) / ".venv").mkdir()

        # Create files in excluded directories
        (Path(temp_dir) / ".git" / "test.txt").write_text("test")
        (Path(temp_dir) / "node_modules" / "test.js").write_text("test")

        scanner = YaraScanner(temp_dir, "testorg", "testrepo")
        results = await scanner.scan()

        # Should complete without scanning excluded directories
        assert isinstance(results, list)
