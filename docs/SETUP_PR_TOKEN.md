# Setting Up PR_CREATE_PAT Token

This guide explains how to create and configure the `PR_CREATE_PAT` token required for automatic pull request creation.

## Why This Token is Needed

The workflow needs to create pull requests with scan results. While GitHub provides a default `GITHUB_TOKEN`, using a Personal Access Token (PAT) allows for better permissions management and ensures PRs can trigger other workflows.

## Steps to Create the Token

### 1. Create a Personal Access Token (Classic)

1. Go to **GitHub Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
   - Direct link: https://github.com/settings/tokens

2. Click **"Generate new token"** → **"Generate new token (classic)"**

3. Configure the token:
   - **Note**: `VMCP PR Creation Token`
   - **Expiration**: Choose based on your needs (30 days, 60 days, or no expiration)

4. Select the following scopes:
   - ✅ `repo` (Full control of private repositories)
     - This includes: `repo:status`, `repo_deployment`, `public_repo`, `repo:invite`, `security_events`
   - ✅ `workflow` (Update GitHub Action workflows)

5. Click **"Generate token"**

6. **IMPORTANT**: Copy the token immediately! You won't be able to see it again.

### 2. Add Token to Repository Secrets

1. Go to your repository: `https://github.com/Alig1493/c-mcp-2`

2. Navigate to **Settings** → **Secrets and variables** → **Actions**

3. Click **"New repository secret"**

4. Configure the secret:
   - **Name**: `PR_CREATE_PAT`
   - **Secret**: Paste the token you copied

5. Click **"Add secret"**

## Verify Setup

To verify the token is working:

1. Go to **Actions** tab
2. Select **"Vulnerability Scan"** workflow
3. Click **"Run workflow"**
4. Enter a test repository URL
5. Check that the workflow:
   - ✅ Completes successfully
   - ✅ Creates a new branch
   - ✅ Creates a pull request

## Token Permissions Breakdown

| Permission | Why Needed |
|------------|------------|
| `repo` | Create branches, commit files, and read repository content |
| `workflow` | Allow PRs to trigger other workflows (if you have PR checks) |

## Security Best Practices

1. **Use Fine-Grained Tokens** (Alternative):
   - Go to: https://github.com/settings/tokens?type=beta
   - Select **"Generate new token"**
   - Choose only the repository: `Alig1493/c-mcp-2`
   - Select permissions:
     - Repository permissions:
       - Contents: **Read and write**
       - Pull requests: **Read and write**
       - Workflows: **Read and write**

2. **Set Token Expiration**: Use 60-90 days and rotate regularly

3. **Limit Token Scope**: Use repository-specific tokens when possible

4. **Monitor Usage**: Check the token's activity in Settings → Developer settings

## Troubleshooting

### Error: "Resource not accessible by integration"

**Solution**: Check that `PR_CREATE_PAT` secret exists and has correct permissions

```bash
# The workflow should have:
env:
  GH_TOKEN: ${{ secrets.PR_CREATE_PAT }}
```

### Error: "Bad credentials"

**Solution**: Token expired or incorrect. Generate a new token and update the secret.

### Error: "Refusing to allow a Personal Access Token to create or update workflow"

**Solution**: Add `workflow` scope to your token.

### PRs Not Being Created

1. Check workflow logs for errors
2. Verify token permissions
3. Ensure branch protection rules don't block bot PRs
4. Check that `scripts/create_scan_pr.sh` is executable

## Alternative: Using GITHUB_TOKEN

If you prefer not to use a PAT, you can use the default `GITHUB_TOKEN`:

```yaml
- name: Create Pull Request
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # Instead of PR_CREATE_PAT
```

**Limitations**:
- PRs created with `GITHUB_TOKEN` won't trigger other workflows
- Less control over permissions
- May have issues with branch protection rules

## Token Maintenance

**Recommended Schedule**:
- Review token usage: Monthly
- Rotate token: Every 90 days
- Update documentation: When changing scopes

**Expiration Reminder**:
Set a calendar reminder 1 week before token expiration to generate and update it.

## Questions?

- **Q: Can multiple people use the same token?**
  - A: Yes, repository secrets are shared across all workflows

- **Q: What if the token is compromised?**
  - A: Immediately revoke it in GitHub Settings → Developer settings → Personal access tokens, then generate a new one

- **Q: Does this work for private repositories?**
  - A: Yes, as long as the token has `repo` scope

- **Q: Can I use organization secrets?**
  - A: Yes, if your repository is part of an organization, you can use organization-level secrets
