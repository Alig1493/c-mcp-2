# VMCP - MCP Vulnerability Scanner

Automated vulnerability scanning platform for MCP (Model Context Protocol) servers. Scan any public GitHub repository and track security vulnerabilities across the MCP ecosystem.

## What This Does

This repository runs automated security scans on MCP servers and stores results centrally. No setup required on target repositories - just provide a URL and get comprehensive vulnerability reports.

**Key Features:**
- 🔍 Scans any public GitHub repository
- 🤖 Auto-detects languages and selects appropriate scanners
- ⚡ Parallel scanner execution for fast results
- 📊 Centralized vulnerability tracking
- 🎯 Sorted by security status (cleanest MCPs first)

## Quick Start

### Using Makefile (Recommended)

```bash
# Scan with all scanners (auto-detect)
make scan REPO_URL=https://github.com/org/mcp-repo

# Scan with specific scanner
make scan REPO_URL=https://github.com/org/mcp-repo SCANNERS=trivy

# Scan with multiple scanners
make scan REPO_URL=https://github.com/org/mcp-repo SCANNERS=trivy,osv-scanner,semgrep,yara
```

### Using GitHub Actions UI

1. **Trigger a scan**: Go to Actions → "Vulnerability Scan" → Run workflow
2. **Input repository URL**: `https://github.com/org/mcp-repo`
3. **View results**: Check [SCAN_RESULTS.md](SCAN_RESULTS.md) for the summary table

## How It Works

```
User Triggers Workflow
         ↓
Clone Target Repository
         ↓
Detect Languages → Select Scanners
         ↓
┌────────────────────────────┐
│  Run Scanners (Parallel)   │
│  • Trivy                    │
│  • OSV Scanner              │
│  • Semgrep                  │
│  • YARA                     │
└────────────────────────────┘
         ↓
Aggregate Results
         ↓
Generate SCAN_RESULTS.md
         ↓
Create Pull Request
```

**Target Repository**: Never modified - scanned in isolation
**Your Repository**: Stores all vulnerability data in `results/` directory

## Scanners

### Trivy
Container and filesystem vulnerability scanner. Detects CVEs in dependencies, OS packages, and application libraries.

**What it finds:** Known CVEs, outdated packages, security issues in container images

### OSV Scanner
Open Source Vulnerability database scanner. Checks dependencies against OSV database covering multiple ecosystems (PyPI, npm, Go, etc.).

**What it finds:** Vulnerabilities in open source dependencies with detailed remediation info

### Semgrep
Static analysis security testing (SAST) tool. Analyzes source code for security patterns and potential vulnerabilities.

**What it finds:** SQL injection, XSS, insecure crypto, hardcoded secrets, code quality issues

### YARA
Malware and threat detection scanner using pattern matching. Detects suspicious code patterns, backdoors, obfuscation, and known malware signatures.

**What it finds:** Malicious code patterns and backdoors, known malware signatures (5290 rules), suspicious behavior (command injection, file manipulation), code obfuscation and anti-analysis techniques, credential harvesting patterns

**Rules:** Uses [yara-forge-rules-core](https://yarahq.github.io/) with 5290 curated rules

**What YARA helps us do:** YARA complements existing scanners by detecting malicious intent and behavior rather than just vulnerable code. While Semgrep finds coding mistakes (SQL injection, XSS), Trivy/OSV find known CVEs in dependencies, YARA identifies whether the code itself is malicious, contains backdoors, or exhibits suspicious patterns commonly found in malware.

**Information YARA provides (vs. other scanners):**
- **Behavioral Detection**: Identifies malicious patterns (crypto-mining, data exfiltration, C2 communication)
- **Malware Signatures**: Matches known malware families and variants
- **Code Fingerprinting**: Detects obfuscation, packing, and anti-analysis techniques
- **Contextual Matches**: Shows exactly which strings/patterns matched and where
- **Rule Provenance**: Includes rule author, date, and source repository for traceability

**Rule Source:** YARA rules are curated and maintained by the YARA community through [YARA-Forge](https://yarahq.github.io/), a collaborative platform for high-quality YARA rules. The core ruleset includes contributions from security researchers worldwide and is regularly updated with new threat intelligence.

## Results Format

### SCAN_RESULTS.md
Summary table with all scanned MCPs:

| Project | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |
|---------|-------|----------|------|--------|-----|---------|----------|--------|
| [org/repo](results/org/repo/violations.json) | 5 | 0 | 1 | 3 | 1 | 2 | trivy, osv-scanner, semgrep | 🟡 |

**Sorted by security status**: MCPs with zero vulnerabilities appear first

### violations.json
Detailed findings per repository:

```json
{
  "org/repo": {
    "trivy": [
      {
        "id": "CVE-2024-1234",
        "severity": "HIGH",
        "summary": "Vulnerability description",
        "fixed_version": "1.2.3",
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}]
      }
    ],
    "semgrep": [...],
    "osv-scanner": [...]
  }
}
```

## GitHub Actions Workflow

The workflow runs automatically when triggered:

1. **Setup**: Install Python, scanners, dependencies
2. **Matrix Scan**: Run each scanner in parallel on separate runners
3. **Aggregate**: Merge all scanner results into single `violations.json`
4. **Report**: Generate `SCAN_RESULTS.md` with summary table
5. **PR Creation**: Automatically create pull request with findings

**Advantages:**
- Fast execution (parallel scanning)
- No data loss (scanner results merged properly)
- Clean results (scanner-specific files removed after aggregation)

## Installation

### Prerequisites
- Python 3.13+
- uv package manager
- Git

### Local Usage

```bash
# Clone the repository
git clone https://github.com/Alig1493/v-mcp-2.git
cd v-mcp-2

# Install dependencies
uv sync

# Scan a repository
uv run python -m vmcp.cli scan https://github.com/org/mcp-repo --output-dir results

# Aggregate results
uv run python -m vmcp.cli aggregate --results-dir results
```

## Project Structure

```
v-mcp-2/
├── src/vmcp/
│   ├── cli.py              # CLI entry point
│   ├── models.py           # Vulnerability data models
│   ├── orchestrator.py     # Parallel scanner execution
│   ├── scanners/           # Scanner implementations
│   │   ├── trivy.py
│   │   ├── osv.py
│   │   ├── semgrep.py
│   │   └── yara.py
│   └── utils/
│       ├── detect_language.py     # Language detection
│       ├── aggregate_results.py   # Results merging
│       └── enhance_cve_links.py   # CVE link validation
├── .github/workflows/
│   └── scan-repo.yml       # GitHub Actions workflow
├── results/                # Scan results (generated)
├── SCAN_RESULTS.md        # Summary table (generated)
└── README.md              # This file
```

## Configuration

### Workflow Inputs

- **repo_url** (required): GitHub repository URL to scan
- **scanners** (optional): Comma-separated list of scanners, leave empty for auto-detect

### Examples

```yaml
# Auto-detect scanners
repo_url: https://github.com/org/mcp-repo
scanners:

# Specific scanners only
repo_url: https://github.com/org/mcp-repo
scanners: trivy,osv-scanner,semgrep,yara
```

## License

MIT License

## Contributing

Contributions welcome! Open an issue or pull request.
