# Lab 2.4: GitHub Advanced Security and Automated Scanning

## Overview

This lab covers GitHub Advanced Security (GHAS), Dependabot, and automated security workflows for continuous vulnerability detection.

## Learning Objectives

By the end of this lab, you will:
- Understand GitHub Advanced Security features
- Configure Dependabot for dependency updates
- Set up CodeQL for code scanning
- Create automated security workflows
- Implement security policies and best practices

## Prerequisites

- Completed all previous labs
- GitHub account
- Repository with code (can be a test project)
- Basic understanding of CI/CD

## Part 1: GitHub Advanced Security (GHAS) Overview

### What is GHAS?

GitHub Advanced Security provides:
1. **Code Scanning** - Find security vulnerabilities with CodeQL
2. **Secret Scanning** - Detect committed secrets
3. **Dependency Review** - Review dependency changes in PRs
4. **Security Advisories** - Private vulnerability reporting

### Availability
- **Free**: Public repositories
- **Paid**: Private repositories (GitHub Enterprise)

## Part 2: Setting Up Dependabot

### What is Dependabot?

Dependabot automatically:
- Checks for outdated dependencies
- Creates pull requests with updates
- Provides vulnerability information
- Supports multiple package ecosystems

### Exercise 1: Enable Dependabot

#### Step 1: Create Dependabot Configuration

Create `.github/dependabot.yml`:

```yaml
# .github/dependabot.yml
version: 2
updates:
  # Enable version updates for npm
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 10
    reviewers:
      - "your-team"
    assignees:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    commit-message:
      prefix: "chore"
      include: "scope"

  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      # Group minor and patch updates
      development-dependencies:
        dependency-type: "development"
        update-types:
          - "minor"
          - "patch"

  # Docker base images
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "docker"
      - "security"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
    labels:
      - "ci/cd"
```

#### Step 2: Enable Security Updates

1. Go to repository → **Settings** → **Security & analysis**
2. Enable **Dependabot alerts**
3. Enable **Dependabot security updates**
4. (Optional) Enable **Dependabot version updates**

### Exercise 2: Handle Dependabot PRs

When Dependabot creates a PR:

```bash
# 1. Review the PR
# - Check changelog
# - Review dependency vulnerabilities
# - Look at compatibility notes

# 2. Test locally
git fetch origin
git checkout dependabot/npm_and_yarn/lodash-4.17.21

# 3. Run tests
npm install
npm test

# 4. Check for breaking changes
npm run build
npm run lint

# 5. Approve and merge if tests pass
```

## Part 3: CodeQL Code Scanning

### What is CodeQL?

CodeQL is a semantic code analysis engine that:
- Finds security vulnerabilities
- Detects code quality issues
- Supports multiple languages
- Runs on every push/PR

### Exercise 3: Enable CodeQL

#### Step 1: Create CodeQL Workflow

Create `.github/workflows/codeql-analysis.yml`:

```yaml
name: "CodeQL"

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run at 6 AM UTC every Monday
    - cron: '0 6 * * 1'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [ 'javascript', 'python' ]
        # Supported: 'cpp', 'csharp', 'go', 'java', 'javascript', 'python', 'ruby'

    steps:
    - name: Checkout repository
      uses: actions/checkout@v3

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: ${{ matrix.language }}
        # Override default queries
        queries: security-extended,security-and-quality

    # Autobuild attempts to build compiled languages
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2

    # For manual build:
    # - name: Build
    #   run: |
    #     make bootstrap
    #     make release

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      with:
        category: "/language:${{matrix.language}}"
```

#### Step 2: Custom CodeQL Queries

Create custom security queries in `.github/codeql/custom-queries.ql`:

```ql
/**
 * @name Hard-coded credentials
 * @description Finds potential hard-coded credentials in code
 * @kind problem
 * @problem.severity error
 * @id custom/hardcoded-credentials
 */

import javascript

from StringLiteral str
where
  str.getValue().regexpMatch("(?i).*(password|secret|api[_-]?key|token).*") and
  str.getValue().length() > 8
select str, "Potential hard-coded credential found"
```

### Exercise 4: Review CodeQL Results

1. Go to **Security** → **Code scanning alerts**
2. Review each finding:
   - Severity
   - CWE classification
   - Affected file and line
   - Remediation guidance
3. Fix or dismiss issues
4. Track resolution in security dashboard

## Part 4: Secret Scanning

### What is Secret Scanning?

Automatically detects committed secrets:
- API keys
- Tokens
- Passwords
- Private keys
- Database connection strings

### Exercise 5: Enable Secret Scanning

1. Go to **Settings** → **Security & analysis**
2. Enable **Secret scanning**
3. Enable **Push protection** (prevents committing secrets)

### Exercise 6: Test Secret Scanning

```bash
# Create a test commit with a secret
echo "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > .env
git add .env
git commit -m "Add config"

# If push protection is enabled, this will be blocked
git push

# Expected output:
# ! [remote rejected] main -> main (push declined due to secret scanning)
```

### Exercise 7: Handle Secret Leaks

If a secret is committed:

1. **Immediate Actions:**
```bash
# DO NOT just delete the file in a new commit!
# The secret is still in Git history

# Option 1: Use BFG Repo-Cleaner
bfg --replace-text passwords.txt repo.git

# Option 2: Use git-filter-repo
git filter-repo --path .env --invert-paths
```

2. **Rotate the Secret:**
   - Immediately invalidate the exposed secret
   - Generate new credentials
   - Update all services using the secret

3. **Review Access Logs:**
   - Check if the secret was used maliciously
   - Monitor for suspicious activity

## Part 5: Comprehensive Security Workflow

### Exercise 8: Complete Security Pipeline

Create `.github/workflows/security-full.yml`:

```yaml
name: Security Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  dependency-check:
    name: Dependency Security Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run npm audit
        run: npm audit --audit-level=high

      - name: Check for outdated packages
        run: npm outdated || true

  sast:
    name: Static Application Security Testing
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten

  container-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Grype scan
        uses: anchore/scan-action@v3
        with:
          image: myapp:${{ github.sha }}
          fail-build: true
          severity-cutoff: high

      - name: Upload scan results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

  secrets-scan:
    name: Secrets Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history

      - name: TruffleHog scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  license-check:
    name: License Compliance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check licenses
        uses: pilosus/action-pip-license-checker@v2
        with:
          requirements: 'requirements.txt'
          fail: 'Copyleft,Other'
          exclude: '(^test.*|^dev.*)'
```

### Exercise 9: Security Policy

Create `SECURITY.md`:

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
- Email: security@example.com
- GitHub Security Advisories (recommended)

Include:
- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-30 days
  - Medium: 30-90 days

## Security Update Process

1. Vulnerability reported
2. Team investigates and confirms
3. Fix developed in private fork
4. Security advisory created
5. Fix released with CVE (if applicable)
6. Public disclosure after fix is available

## Automated Security

This repository uses:
- **Dependabot**: Automatic dependency updates
- **CodeQL**: Code vulnerability scanning
- **Secret Scanning**: Committed secret detection
- **Grype**: Container vulnerability scanning

## Best Practices

### For Contributors

- Never commit secrets
- Use `.env.example` for environment templates
- Run `npm audit` before submitting PRs
- Follow secure coding guidelines

### For Maintainers

- Review Dependabot PRs weekly
- Triage security alerts within 24 hours
- Keep dependencies updated
- Rotate secrets regularly
```

## Part 6: Monitoring and Metrics

### Exercise 10: Security Dashboard

Create a script to monitor security metrics:

```python
# security_metrics.py
import requests
import os
from datetime import datetime

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO = 'owner/repo'

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

def get_dependabot_alerts():
    url = f'https://api.github.com/repos/{REPO}/dependabot/alerts'
    response = requests.get(url, headers=headers)
    alerts = response.json()

    critical = sum(1 for a in alerts if a['security_advisory']['severity'] == 'critical')
    high = sum(1 for a in alerts if a['security_advisory']['severity'] == 'high')

    return {
        'total': len(alerts),
        'critical': critical,
        'high': high
    }

def get_code_scanning_alerts():
    url = f'https://api.github.com/repos/{REPO}/code-scanning/alerts'
    response = requests.get(url, headers=headers)
    alerts = response.json()

    return {
        'total': len(alerts),
        'open': sum(1 for a in alerts if a['state'] == 'open')
    }

def generate_report():
    print(f"Security Report - {datetime.now().isoformat()}")
    print("=" * 50)

    dependabot = get_dependabot_alerts()
    print(f"\nDependabot Alerts:")
    print(f"  Total: {dependabot['total']}")
    print(f"  Critical: {dependabot['critical']}")
    print(f"  High: {dependabot['high']}")

    code_scanning = get_code_scanning_alerts()
    print(f"\nCode Scanning Alerts:")
    print(f"  Total: {code_scanning['total']}")
    print(f"  Open: {code_scanning['open']}")

if __name__ == '__main__':
    generate_report()
```

## Verification Checklist

- [ ] Enabled Dependabot alerts and updates
- [ ] Created Dependabot configuration
- [ ] Set up CodeQL code scanning
- [ ] Enabled secret scanning with push protection
- [ ] Created comprehensive security workflow
- [ ] Wrote security policy (SECURITY.md)
- [ ] Tested automated security checks
- [ ] Reviewed and triaged security alerts

## Best Practices

### Automation
1. **Run scans frequently** - Every commit, PR, and daily
2. **Fail fast** - Block PRs with critical issues
3. **Auto-merge safe updates** - Use Dependabot auto-merge for patch updates
4. **Monitor metrics** - Track security posture over time

### Response
1. **Prioritize by severity** - Critical/High first
2. **Set SLAs** - Response times for each severity
3. **Document decisions** - Why alerts were dismissed
4. **Communicate** - Keep team informed

### Prevention
1. **Security training** - Regular team education
2. **Secure coding guidelines** - Documented standards
3. **Pre-commit hooks** - Catch issues before commit
4. **Regular audits** - Periodic manual reviews

## Discussion Questions

1. What's the difference between Dependabot and CodeQL?
2. Why is secret scanning important even with .gitignore?
3. How do you balance security with development velocity?
4. What should you do if a critical vulnerability has no fix available?
5. How does automated scanning fit into a defense-in-depth strategy?

## Additional Challenges

1. Set up custom CodeQL queries for your domain
2. Create a security metrics dashboard
3. Implement automated alert triage with labels
4. Build a security champion program
5. Create runbooks for common vulnerability types

## Course Completion

Congratulations! You've completed the Privacy-Conscious Development course. You now know how to:

✅ Understand privacy risks in AI-assisted development
✅ Use Claude Code, Windsurf, and other AI tools securely
✅ Apply secure prompting techniques
✅ Prevent SQL injection
✅ Implement secure file uploads
✅ Configure HTTP security headers
✅ Scan containers with Grype
✅ Set up GitHub Advanced Security
✅ Automate security workflows

### Next Steps

1. Apply these practices to your projects
2. Share knowledge with your team
3. Contribute to security communities
4. Stay updated on emerging threats
5. Practice continuous learning

## Additional Resources

- [GitHub Security Docs](https://docs.github.com/en/code-security)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Dependabot Configuration Reference](https://docs.github.com/en/code-security/dependabot)
- [GHAS Best Practices](https://github.blog/2021-08-31-github-advanced-security-security-overview/)
- [Security Champions Playbook](https://github.com/c0rdis/security-champions-playbook)
