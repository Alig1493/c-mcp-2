#!/bin/bash
set -e

# ============================================================================
# Configuration
# ============================================================================
BRANCH_PREFIX="auto-update-readme"
PR_TITLE="Update MCP Vulnerabilities Summary in README"
PR_LABELS="automated,documentation"

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
# Main Script
# ============================================================================
USER_INFO=$(determine_git_user)
GIT_USER=$(echo "${USER_INFO}" | cut -d'|' -f1)
GIT_EMAIL=$(echo "${USER_INFO}" | cut -d'|' -f2)

echo "📝 Git User: ${GIT_USER} <${GIT_EMAIL}>"

BRANCH_NAME="${BRANCH_PREFIX}-$(date +%s)"

# Configure git
git config --local user.name "${GIT_USER}"
git config --local user.email "${GIT_EMAIL}"

# Create branch and commit
git checkout -b "${BRANCH_NAME}"
git add README.md
git commit -m "chore: update MCP vulnerabilities summary

Event: ${GITHUB_EVENT_NAME}
Triggered-by: ${GIT_USER}
Workflow: ${GITHUB_WORKFLOW}"

git push -u origin "${BRANCH_NAME}"

# Prepare PR body
PR_BODY="## 📊 Automated README Update

Updates the MCP Vulnerabilities Summary based on \`violations.json\`.

**Triggered by:** @${GIT_USER}  
**Event:** \`${GITHUB_EVENT_NAME}\`  
**Run ID:** [${GITHUB_RUN_ID}](https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID})

---

🤖 Generated with GitHub Actions"

# Create PR with conditional assignment (without labels initially)
if [[ "${GIT_USER}" == *"[bot]"* ]]; then
  echo "🤖 Creating bot PR (no assignment)"
  set +e  # Temporarily disable exit on error
  PR_URL=$(gh pr create \
    --title "${PR_TITLE}" \
    --body "${PR_BODY}" 2>&1)
  PR_EXIT_CODE=$?
  set -e  # Re-enable exit on error
else
  echo "👤 Creating user PR with assignment to ${GIT_USER}"
  set +e  # Temporarily disable exit on error
  PR_URL=$(gh pr create \
    --title "${PR_TITLE}" \
    --body "${PR_BODY}" \
    --assignee "${GIT_USER}" 2>&1)
  PR_EXIT_CODE=$?
  set -e  # Re-enable exit on error
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

  # Try to add labels, but don't fail if they don't exist
  IFS=',' read -ra LABEL_ARRAY <<< "${PR_LABELS}"
  for label in "${LABEL_ARRAY[@]}" ; do
    # Try to create label if it doesn't exist
    if gh label create "${label}" --description "Auto-generated label" --color "0e8a16" 2>/dev/null; then
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