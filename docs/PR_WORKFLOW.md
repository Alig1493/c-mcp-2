# Pull Request Workflow for Vulnerability Scans

This document explains how the automated PR workflow works for vulnerability scan results.

## Overview

Instead of committing directly to `main`, the workflow creates a pull request with scan results. This allows for:
- ✅ Review before merging
- ✅ Discussion of findings
- ✅ Triggering additional PR checks
- ✅ Audit trail of scans
- ✅ Approval workflow

## How It Works

### 1. Trigger Scan

```
User triggers workflow → Workflow scans repository → PR created automatically
```

### 2. Branch Naming

Branch name format: `scan-results/<org>-<repo>-<timestamp>`

Example: `scan-results/django-django-1702651234`

### 3. PR Creation

**PR Title**: `🔒 Add vulnerability scan results for {org}/{repo}`

**PR Body** includes:
- Target repository link
- Vulnerability count summary
- List of files changed
- Scanners used
- Review checklist
- Metadata (triggered by, run ID, etc.)

### 4. PR Labels

Automatically added labels:
- `automated` - Indicates automated PR
- `security` - Security-related changes
- `vulnerability-scan` - Specific to vulnerability scanning

### 5. File Changes

Each PR includes:
```
+ results/<org>/<repo>/violations.json  (new scan data)
± SCAN_RESULTS.md                       (updated summary)
```

## Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  User triggers "Vulnerability Scan" workflow                 │
│  Input: https://github.com/django/django                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Workflow Execution                                          │
│  1. Clone target repo                                        │
│  2. Run scanners (Trivy, OSV, Semgrep)                      │
│  3. Save to results/django/django/violations.json           │
│  4. Aggregate results to SCAN_RESULTS.md                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  PR Creation (scripts/create_scan_pr.sh)                    │
│  1. Create branch: scan-results/django-django-1702651234   │
│  2. Commit files: results/ + SCAN_RESULTS.md               │
│  3. Push branch                                             │
│  4. Create PR with GH CLI                                   │
│  5. Add labels                                              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Pull Request Created                                        │
│  Status: Open                                                │
│  Ready for review                                            │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Manual Review                                               │
│  - Check SCAN_RESULTS.md for summary                        │
│  - Review violations.json for details                       │
│  - Verify CVE links                                         │
│  - Approve and merge                                        │
└─────────────────────────────────────────────────────────────┘
```

## PR Review Checklist

When reviewing a vulnerability scan PR:

1. **Check Summary**:
   - [ ] Open `SCAN_RESULTS.md`
   - [ ] Note total findings and worst severity
   - [ ] Verify scanned repository is correct

2. **Review Details**:
   - [ ] Open `results/<org>/<repo>/violations.json`
   - [ ] Review high/critical severity issues
   - [ ] Check if fixed versions are available

3. **Validate Links**:
   - [ ] Click on CVE reference links
   - [ ] Ensure they point to correct vulnerability pages

4. **Next Actions**:
   - [ ] Create issues for critical findings
   - [ ] Plan remediation for high-severity issues
   - [ ] Document false positives if any

5. **Merge Decision**:
   - [ ] Merge to add results to repository
   - [ ] Or close if scan was exploratory

## Example PR

**Title**: `🔒 Add vulnerability scan results for django/django`

**Body**:
```markdown
## 🔒 Vulnerability Scan Results

Automated security scan for: **[django/django](https://github.com/django/django)**

**Total Vulnerabilities Found:** 42

### 📊 What's Included

- `results/django/django/violations.json` - Detailed vulnerability data
- `SCAN_RESULTS.md` - Aggregated summary table

### 🔍 Scanners Used

- **Trivy** - Container and filesystem vulnerabilities
- **OSV Scanner** - Open source vulnerability database
- **Semgrep** - Static analysis security testing

### 📝 Review Checklist

- [ ] Review `SCAN_RESULTS.md` for severity summary
- [ ] Check `violations.json` for detailed findings
- [ ] Verify CVE links are working
- [ ] Decide on next actions for high-severity issues

---

**Triggered by:** @github-actions[bot]
**Event:** `workflow_dispatch`
**Run ID:** [12345678](...)

🤖 Generated with VMCP
```

**Files Changed**:
- `results/django/django/violations.json` (+500 lines)
- `SCAN_RESULTS.md` (+15 lines)

**Labels**: `automated`, `security`, `vulnerability-scan`

## Managing PRs

### View All Scan PRs

```bash
gh pr list --label vulnerability-scan
```

### Auto-Merge (Optional)

If you trust the process, you can auto-merge:

```yaml
# Add to workflow after PR creation
- name: Auto-merge PR
  if: success()
  run: |
    gh pr merge --auto --merge "${PR_URL}"
```

### Close Stale PRs

```bash
# Close PRs older than 30 days
gh pr list --label vulnerability-scan --state open \
  --json number,createdAt --jq '.[] | select(.createdAt | fromdateiso8601 < (now - 2592000)) | .number' \
  | xargs -I {} gh pr close {}
```

## Conflict Resolution

If a PR has conflicts (usually with `SCAN_RESULTS.md`):

1. **Option A - Merge Main**:
   ```bash
   gh pr checkout <PR_NUMBER>
   git merge main
   git push
   ```

2. **Option B - Rebase**:
   ```bash
   gh pr checkout <PR_NUMBER>
   git rebase main
   git push --force
   ```

3. **Option C - Close and Rescan**:
   - Close the old PR
   - Trigger a new scan
   - New PR will have up-to-date base

## Customization

### Change Branch Prefix

Edit `scripts/create_scan_pr.sh`:
```bash
BRANCH_PREFIX="security-scan"  # Instead of "scan-results"
```

### Modify PR Template

Edit the `PR_BODY` variable in `scripts/create_scan_pr.sh` to customize:
- Additional sections
- Different checklist items
- Custom formatting

### Add Reviewers

Edit the PR creation command:
```bash
gh pr create \
  --title "${PR_TITLE}" \
  --body "${PR_BODY}" \
  --reviewer "your-team-name"  # Add this
```

### Require Approvals

In repository settings:
1. Go to **Settings** → **Branches**
2. Add branch protection rule for `main`
3. Check "Require pull request reviews before merging"
4. Set required approvals: 1 or more

## Troubleshooting

### PR Not Created

**Check**:
1. `PR_CREATE_PAT` secret exists and is valid
2. Workflow has `pull-requests: write` permission
3. Script is executable: `chmod +x scripts/create_scan_pr.sh`
4. Check workflow logs for errors

### Labels Not Added

**Reason**: Labels don't exist in repository

**Solution**: Script auto-creates labels, but check that token has permission

### Multiple PRs for Same Repo

**Behavior**: Each scan creates a new PR

**Management**:
- Close old PRs manually
- Or implement PR update logic instead of create

## Best Practices

1. **Regular Scans**: Schedule weekly or monthly scans
2. **Quick Review**: Review PRs within 24-48 hours
3. **Track Progress**: Use issues for remediation tracking
4. **Archive Results**: Keep historical scan data
5. **Update Tokens**: Rotate `PR_CREATE_PAT` every 90 days

## Questions?

**Q: Can I commit directly instead of PR?**
A: Yes, remove the PR creation step and use direct commit (previous behavior)

**Q: How do I disable auto-labeling?**
A: Set `PR_LABELS=""` in `scripts/create_scan_pr.sh`

**Q: Can I scan the same repo multiple times?**
A: Yes, each scan creates a new PR with unique branch name

**Q: What if I want to update existing PR?**
A: Modify script to check for existing PR and update it instead of creating new one
