# Quick Start Guide

## Setup (One Time)

1. **Push this repo to GitHub**:
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/v-mcp-2.git
   git push -u origin main
   ```

2. **Verify workflow is enabled**:
   - Go to repository Settings → Actions → General
   - Ensure "Allow all actions and reusable workflows" is enabled

## Scan a Repository

### Via GitHub UI (Recommended)

1. Navigate to **Actions** tab
2. Click **"Vulnerability Scan"** in left sidebar
3. Click **"Run workflow"** button (right side)
4. Fill in the form:
   - **repo_url**: `https://github.com/org/repo` (required)
   - **scanners**: Leave empty for auto-detect, or specify: `trivy,semgrep,osv-scanner`
5. Click **"Run workflow"** (green button)

### Via CLI (Advanced)

```bash
# Install GitHub CLI
gh workflow run scan-repo.yml \
  -f repo_url=https://github.com/facebook/react \
  -f scanners=""  # empty for auto-detect
```

### Via API

```bash
curl -X POST \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/YOUR_USERNAME/v-mcp-2/actions/workflows/scan-repo.yml/dispatches \
  -d '{"ref":"main","inputs":{"repo_url":"https://github.com/org/repo"}}'
```

## View Results

### Check Workflow Status

1. Go to **Actions** tab
2. Click on the running/completed workflow
3. View logs for each step

### See Scan Results

**Option 1 - Download Artifacts**:
- In workflow run → **Artifacts** section
- Download `scan-results.zip`

**Option 2 - View in Repository**:
- Wait for workflow to complete
- Results auto-committed to `results/` folder
- README.md updated with summary table

**Option 3 - Browse Files**:
```
results/
└── org/
    └── repo/
        └── violations.json  ← All vulnerabilities here
```

## Example Scans

### Scan Python Project
```
repo_url: https://github.com/django/django
scanners: (auto-detect)
```
→ Runs: Trivy + Semgrep

### Scan JavaScript Project
```
repo_url: https://github.com/facebook/react
scanners: (auto-detect)
```
→ Runs: Trivy + Semgrep + OSV Scanner

### Scan with Specific Scanners
```
repo_url: https://github.com/any/project
scanners: trivy,osv-scanner
```
→ Runs: Only Trivy + OSV Scanner (skips Semgrep)

## Understanding Results

### violations.json Structure
```json
{
  "org/repo": {
    "trivy": [
      {
        "id": "CVE-2024-1234",
        "severity": "HIGH",
        "summary": "SQL Injection vulnerability",
        "details": "Detailed description...",
        "affected_range": "1.0.0",
        "fixed_version": "1.0.1",
        "references": [
          {
            "type": "web",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
          }
        ],
        "scores": [
          {
            "type": "cvss",
            "value": 7.5,
            "version": "3.0"
          }
        ]
      }
    ]
  }
}
```

### SCAN_RESULTS.md Table
```markdown
| Project | Total | Critical | High | Medium | Low | Fixable | Scanners | Status |
|---------|-------|----------|------|--------|-----|---------|----------|--------|
| [org/repo](results/org/repo/violations.json) | 42 | 5 | 12 | 20 | 5 | 18 | trivy, osv-scanner, semgrep | 🔴 |
```

**Column Breakdown**:
- **Project**: Clickable link to detailed violations.json
- **Total**: Total vulnerabilities found across all scanners
- **Critical/High/Medium/Low**: Severity breakdown for prioritization
- **Fixable**: Count of vulnerabilities with available patches/fixes
- **Scanners**: Which security tools were used
- **Status**: 🔴 Critical/High | 🟡 Medium/Low | 🟢 None

**Quick Actions**:
- Focus on **Critical** and **High** first (immediate security risks)
- Use **Fixable** count to estimate remediation effort
- Verify all expected **Scanners** ran successfully

## Troubleshooting

### Workflow Fails to Clone
**Error**: `fatal: could not read from remote repository`
**Solution**: Ensure repository URL is correct and public

### No Scanners Found
**Error**: `Selected scanners: []`
**Solution**: Repository may have no recognized language files

### Trivy Not Found
**Error**: `trivy: command not found`
**Solution**: Check workflow logs - scanner installation may have failed

### Permission Denied on Commit
**Error**: `permission denied to github-actions[bot]`
**Solution**:
1. Go to Settings → Actions → General
2. Workflow permissions → Select "Read and write permissions"
3. Re-run workflow

## Scanning Multiple Repositories

### Batch Scanning Script
Create `scan-multiple.sh`:
```bash
#!/bin/bash
REPOS=(
  "https://github.com/django/django"
  "https://github.com/facebook/react"
  "https://github.com/golang/go"
)

for repo in "${REPOS[@]}"; do
  gh workflow run scan-repo.yml -f repo_url="$repo"
  sleep 5  # Avoid rate limiting
done
```

Run:
```bash
chmod +x scan-multiple.sh
./scan-multiple.sh
```

## Advanced Usage

### Local Testing
```bash
# Install dependencies
uv sync

# Scan a repository locally
uv run vmcp scan https://github.com/org/repo --output-dir ./local-results

# Aggregate results
uv run vmcp aggregate --results-dir ./local-results
```

### Custom Scanner Configuration

Edit workflow to add more scanners:
```yaml
- name: Install custom scanner
  run: |
    # Install your scanner
    npm install -g snyk
```

Then update [orchestrator.py](src/vmcp/orchestrator.py:13-18):
```python
SCANNER_MAP = {
    'trivy': TrivyScanner,
    'osv-scanner': OSVScanner,
    'semgrep': SemgrepScanner,
    'snyk': SnykScanner,  # Add your scanner
}
```

## Best Practices

1. **Start Small**: Test with a small repository first
2. **Use Auto-Detect**: Let the system choose scanners initially
3. **Review Regularly**: Set up a schedule to re-scan repositories
4. **Filter Results**: Focus on HIGH/CRITICAL severities first
5. **Track Progress**: Use git history to see vulnerability trends

## Getting Help

- **Documentation**: See [README.md](README.md) for full docs
- **Architecture**: See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for technical details
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development
- **Issues**: Open an issue on GitHub

---

**You're ready to start scanning! 🚀**
