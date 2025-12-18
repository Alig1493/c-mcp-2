.PHONY: scan scan-tool help

# Default target shows help
.DEFAULT_GOAL := help

# Repository to scan (required)
REPO_URL ?=

# Scanners to use (optional, defaults to all)
# Can be: empty (all scanners), single scanner, or comma-separated list
# Examples: trivy, "trivy,osv-scanner", "trivy,osv-scanner,semgrep"
SCANNERS ?=

# GitHub repository where workflow is located
GH_REPO := Alig1493/v-mcp-2

help:
	@echo "VMCP - MCP Vulnerability Scanner Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make scan REPO_URL=<github-url> [SCANNERS=<scanners>]"
	@echo "  make scan-tool REPO_URL=<github-url> [SCANNERS=<scanners>]"
	@echo ""
	@echo "Commands:"
	@echo "  scan       - Scan repository and group vulnerabilities by scanner"
	@echo "  scan-tool  - Scan repository and group vulnerabilities by MCP tool"
	@echo ""
	@echo "Parameters:"
	@echo "  REPO_URL   - GitHub repository URL to scan (required)"
	@echo "  SCANNERS   - Scanners to use (optional, defaults to all)"
	@echo "               Can be: trivy, osv-scanner, semgrep, yara, or comma-separated list"
	@echo "               Leave empty for auto-detect (all scanners)"
	@echo ""
	@echo "Examples:"
	@echo "  # Regular scan with all scanners (auto-detect)"
	@echo "  make scan REPO_URL=https://github.com/BurtTheCoder/mcp-maigret"
	@echo ""
	@echo "  # Tool-based scan with all scanners"
	@echo "  make scan-tool REPO_URL=https://github.com/BurtTheCoder/mcp-maigret"
	@echo ""
	@echo "  # Scan with specific scanner"
	@echo "  make scan REPO_URL=https://github.com/BurtTheCoder/mcp-maigret SCANNERS=yara"
	@echo ""
	@echo "  # Tool-based scan with multiple scanners"
	@echo "  make scan-tool REPO_URL=https://github.com/BurtTheCoder/mcp-maigret SCANNERS=trivy,semgrep"

scan:
	@if [ -z "$(REPO_URL)" ]; then \
		echo "Error: REPO_URL is required"; \
		echo ""; \
		make help; \
		exit 1; \
	fi
	@echo "Triggering vulnerability scan workflow..."
	@echo "Repository: $(REPO_URL)"
	@if [ -z "$(SCANNERS)" ]; then \
		echo "Scanners: auto-detect (all)"; \
		gh workflow run scan-repo.yml --repo $(GH_REPO) -f repo_url=$(REPO_URL) -f scanners=""; \
	else \
		echo "Scanners: $(SCANNERS)"; \
		gh workflow run scan-repo.yml --repo $(GH_REPO) -f repo_url=$(REPO_URL) -f scanners="$(SCANNERS)"; \
	fi
	@echo ""
	@echo "Workflow triggered successfully!"
	@echo "View workflow runs: https://github.com/$(GH_REPO)/actions"

scan-tool:
	@if [ -z "$(REPO_URL)" ]; then \
		echo "Error: REPO_URL is required"; \
		echo ""; \
		make help; \
		exit 1; \
	fi
	@echo "Triggering tool-based vulnerability scan workflow..."
	@echo "Repository: $(REPO_URL)"
	@if [ -z "$(SCANNERS)" ]; then \
		echo "Scanners: auto-detect (all)"; \
		gh workflow run scan-repo.yml --repo $(GH_REPO) -f repo_url=$(REPO_URL) -f scanners="" -f command=scan-tool; \
	else \
		echo "Scanners: $(SCANNERS)"; \
		gh workflow run scan-repo.yml --repo $(GH_REPO) -f repo_url=$(REPO_URL) -f scanners="$(SCANNERS)" -f command=scan-tool; \
	fi
	@echo ""
	@echo "Workflow triggered successfully!"
	@echo "View workflow runs: https://github.com/$(GH_REPO)/actions"
