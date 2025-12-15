#!/bin/bash
set -e

# ============================================================================
# Configuration
# ============================================================================
BRANCH_PREFIX="scan-results"
PR_LABELS="automated,security,vulnerability-scan"

# ============================================================================
# Determine Git User
# ============================================================================
determine_git_user() {
  local actor="${GITHUB_ACTOR:-github-actions[bot]}"
  local email

  # For scheduled runs, use repository owner
  if [[ "${GITHUB_EVENT_NAME}" == "schedule" ]]; then
    actor="${GITHUB_REPOSITORY_OWNER:-github-actions[bot]}"
  fi

  # Set email format
  if [[ "${actor}" == *"[bot]" ]]; then
    email="41898282+${actor}@users.noreply.github.com"
  else
    email="${actor}@users.noreply.github.com"
  fi

  echo "${actor}|${email}"
}

# ============================================================================
# Parse Repository URL
# ============================================================================
REPO_URL="${1:-unknown}"
echo "📦 Scanning repository: ${REPO_URL}"

# Extract org/repo from URL
if [[ "${REPO_URL}" =~ github\.com[/:]([^/]+)/([^/\.]+) ]]; then
  ORG_NAME="${BASH_REMATCH[1]}"
  REPO_NAME="${BASH_REMATCH[2]}"
  TARGET_REPO="${ORG_NAME}/${REPO_NAME}"
else
  echo "❌ Could not parse repository URL"
  exit 1
fi

echo "🎯 Target: ${TARGET_REPO}"

# ============================================================================
# Main Script
# ============================================================================
USER_INFO=$(determine_git_user)
GIT_USER=$(echo "${USER_INFO}" | cut -d'|' -f1)
GIT_EMAIL=$(echo "${USER_INFO}" | cut -d'|' -f2)

echo "📝 Git User: ${GIT_USER} <${GIT_EMAIL}>"

BRANCH_NAME="${BRANCH_PREFIX}/${TARGET_REPO//\//-}-$(date +%s)"
PR_TITLE="🔒 Add vulnerability scan results for ${TARGET_REPO}"

# Configure git
git config --local user.name "${GIT_USER}"
git config --local user.email "${GIT_EMAIL}"

# Check if there are changes to commit
if ! git diff --quiet || ! git diff --cached --quiet || [[ -n $(git ls-files --others --exclude-standard) ]]; then
  echo "📋 Changes detected, creating PR..."

  # Create branch and commit
  git checkout -b "${BRANCH_NAME}"
  git add results/ SCAN_RESULTS.md
  git commit -m "chore: add vulnerability scan results for ${TARGET_REPO}

Scanned repository: ${REPO_URL}
Event: ${GITHUB_EVENT_NAME}
Triggered-by: ${GIT_USER}
Workflow: ${GITHUB_WORKFLOW}

Results:
- violations.json: results/${ORG_NAME}/${REPO_NAME}/violations.json
- Summary: SCAN_RESULTS.md

🔒 Automated vulnerability scan"

  git push -u origin "${BRANCH_NAME}"

  # Count vulnerabilities if possible
  VIOLATIONS_FILE="results/${ORG_NAME}/${REPO_NAME}/violations.json"
  VULN_SUMMARY=""
  if [[ -f "${VIOLATIONS_FILE}" ]]; then
    # Try to extract vulnerability counts using jq if available
    if command -v jq &> /dev/null; then
      TOTAL_VULNS=$(jq '[.[][] | length] | add' "${VIOLATIONS_FILE}" 2>/dev/null || echo "0")
      VULN_SUMMARY="
**Total Vulnerabilities Found:** ${TOTAL_VULNS}"
    fi
  fi

  # Prepare PR body
  PR_BODY="## 🔒 Vulnerability Scan Results

Automated security scan for: **[${TARGET_REPO}](${REPO_URL})**
${VULN_SUMMARY}

### 📊 What's Included

- \`results/${ORG_NAME}/${REPO_NAME}/violations.json\` - Detailed vulnerability data from all scanners
- \`SCAN_RESULTS.md\` - Aggregated summary table

### 🔍 Scanners Used

- **Trivy** - Container and filesystem vulnerabilities
- **OSV Scanner** - Open source vulnerability database
- **Semgrep** - Static analysis security testing

### 📝 Review Checklist

- [ ] Review \`SCAN_RESULTS.md\` for severity summary
- [ ] Check \`violations.json\` for detailed findings
- [ ] Verify CVE links are working
- [ ] Decide on next actions for high-severity issues

---

**Triggered by:** @${GIT_USER}
**Event:** \`${GITHUB_EVENT_NAME}\`
**Run ID:** [${GITHUB_RUN_ID}](https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID})

🤖 Generated with [VMCP](https://github.com/${GITHUB_REPOSITORY})"

  # Create PR with conditional assignment
  if [[ "${GIT_USER}" == *"[bot]"* ]]; then
    echo "🤖 Creating bot PR (no assignment)"
    set +e
    PR_URL=$(gh pr create \
      --title "${PR_TITLE}" \
      --body "${PR_BODY}" 2>&1)
    PR_EXIT_CODE=$?
    set -e
  else
    echo "👤 Creating user PR with assignment to ${GIT_USER}"
    set +e
    PR_URL=$(gh pr create \
      --title "${PR_TITLE}" \
      --body "${PR_BODY}" \
      --assignee "${GIT_USER}" 2>&1)
    PR_EXIT_CODE=$?
    set -e
  fi

  # Check if PR creation succeeded
  if [[ $PR_EXIT_CODE -ne 0 ]]; then
    echo "❌ PR creation failed:"
    echo "$PR_URL"
    exit 1
  fi

  # Extract PR number from URL
  PR_NUMBER=$(echo "${PR_URL}" | grep -oP '/pull/\K\d+' || echo "")

  # Add labels if PR was created successfully
  if [[ -n "${PR_NUMBER}" ]]; then
    echo "📌 Adding labels to PR #${PR_NUMBER}..."

    IFS=',' read -ra LABEL_ARRAY <<< "${PR_LABELS}"
    for label in "${LABEL_ARRAY[@]}" ; do
      # Try to create label if it doesn't exist
      if gh label create "${label}" --description "Auto-generated label" --color "d73a4a" 2>/dev/null; then
        echo "   ✅ Created label: ${label}"
      fi

      # Try to add label to PR
      if gh pr edit "${PR_NUMBER}" --add-label "${label}" 2>/dev/null; then
        echo "   ✅ Added label: ${label}"
      else
        echo "   ⚠️  Could not add label: ${label} (skipping)"
      fi
    done
  fi

  echo "✅ Pull request created successfully!"
  echo "   URL: ${PR_URL}"
  echo "   Branch: ${BRANCH_NAME}"
  echo "   Author: ${GIT_USER}"
  echo "   Target: ${TARGET_REPO}"
else
  echo "ℹ️  No changes to commit, skipping PR creation"
fi
