# Lab 1.2: Setting Up Claude Code for Privacy-Conscious Development

## Overview

This lab guides you through installing and configuring Claude Code with security-first settings to protect sensitive files and data.

## Learning Objectives

By the end of this lab, you will:
- Install Claude Code CLI tool
- Configure project-specific security settings
- Set up file access permissions (allow/deny rules)
- Test security boundaries
- Establish team-wide security policies

## Prerequisites

- Node.js version 18 or newer
- Claude AI or Claude Console account
- Terminal/command line access
- Git installed

## Part 1: Installation

### Step 1: Install Claude Code

```bash
# Install Claude Code globally via npm
npm install -g claude-code

# Verify installation
claude --version
```

### Step 2: Initial Authentication

```bash
# Start Claude Code (first time will prompt for login)
claude

# Follow the authentication prompts
# You'll be redirected to a browser to log in
```

## Part 2: Project Setup

### Step 1: Create Test Project

```bash
# Create a test directory
mkdir privacy-test-project
cd privacy-test-project

# Initialize Git repository
git init

# Create sample files
mkdir secrets
echo "API_KEY=secret_key_12345" > .env
echo "DB_PASSWORD=supersecret" > secrets/credentials.txt
echo "print('Hello World')" > main.py
```

### Step 2: Configure Claude Code Security Settings

Create the `.claude` directory and security configuration:

```bash
# Create Claude configuration directory
mkdir .claude

# Create settings file
touch .claude/settings.json
```

Edit `.claude/settings.json` with the following content:

```json
{
  "permissions": {
    "deny": [
      ".env",
      ".env.local",
      ".env.production",
      ".env.*",
      "secrets/**",
      "**/*.key",
      "**/*.pem",
      "**/credentials.*",
      "**/*secret*"
    ],
    "allow": [
      "**/*.py",
      "**/*.js",
      "**/*.ts",
      "**/*.md",
      "**/README*"
    ]
  }
}
```

### Step 3: Test Security Boundaries

Start Claude Code and test the security configuration:

```bash
# Start Claude Code in your project
claude
```

In Claude Code, try these prompts:

1. **Test denied access:**
```
Can you read my .env file?
```
Expected: Claude should refuse or be unable to access the file.

2. **Test allowed access:**
```
Can you read main.py?
```
Expected: Claude should successfully read the file.

3. **Test directory restrictions:**
```
Can you list files in the secrets directory?
```
Expected: Claude should be blocked from accessing this directory.

## Part 3: Advanced Security Configuration

### Scenario 1: Allow Specific Environment Files

Modify `.claude/settings.json` to allow reading `.env.example` but deny actual environment files:

```json
{
  "permissions": {
    "deny": [
      ".env",
      ".env.local",
      ".env.production",
      "secrets/**"
    ],
    "allow": [
      ".env.example",
      "**/*.py",
      "**/*.js",
      "**/*.md"
    ]
  }
}
```

### Scenario 2: Protect Database Migrations

```json
{
  "permissions": {
    "deny": [
      ".env*",
      "secrets/**",
      "db/migrations/**",
      "backups/**"
    ],
    "allow": [
      "src/**",
      "tests/**",
      "docs/**"
    ]
  }
}
```

### Scenario 3: Team-Wide Configuration

```bash
# Add settings.json to version control
git add .claude/settings.json
git commit -m "Add Claude Code security configuration"

# This ensures all team members use the same security rules
```

## Part 4: Practical Exercise

### Task: Configure Security for a Web Application

Create a realistic project structure and configure appropriate security rules:

```bash
# Create project structure
mkdir -p web-app/{src,config,tests,docs,secrets}

# Create various files
touch web-app/.env
touch web-app/.env.example
touch web-app/config/database.yml
touch web-app/secrets/api-keys.txt
touch web-app/src/app.js
touch web-app/tests/app.test.js
touch web-app/docs/README.md

cd web-app
```

**Your Task:**
1. Create `.claude/settings.json` that:
   - Denies access to `.env` (but allows `.env.example`)
   - Denies access to `secrets/` directory
   - Denies access to `config/database.yml`
   - Allows access to `src/`, `tests/`, and `docs/`
   - Allows Claude to read but not execute shell scripts

2. Test your configuration by asking Claude to:
   - Read a file in `src/`
   - Read a file in `secrets/`
   - Read `.env` vs `.env.example`

## Verification Checklist

- [ ] Claude Code is installed and authenticated
- [ ] `.claude/settings.json` exists in project root
- [ ] Deny rules prevent access to sensitive files
- [ ] Allow rules permit access to source code
- [ ] Configuration is committed to version control
- [ ] Security boundaries are tested and working

## Common Patterns

### Pattern 1: Development vs Production

```json
{
  "permissions": {
    "deny": [
      ".env.production",
      ".env.staging",
      "secrets/**",
      "**/prod-*"
    ],
    "allow": [
      ".env.development",
      ".env.test",
      "**/*.js",
      "**/*.ts"
    ]
  }
}
```

### Pattern 2: Monorepo Security

```json
{
  "permissions": {
    "deny": [
      "packages/*/secrets/**",
      "packages/*/.env",
      "apps/*/config/production.*"
    ],
    "allow": [
      "packages/*/src/**",
      "packages/*/tests/**",
      "apps/*/src/**"
    ]
  }
}
```

## Best Practices

1. **Always deny by default, allow explicitly**
   - Start with restrictive rules
   - Add allow rules as needed

2. **Use glob patterns effectively**
   - `**/*` matches any file in any subdirectory
   - `*.env` matches at current level only
   - `**/*.env` matches at any level

3. **Version control your security settings**
   - Commit `.claude/settings.json` to Git
   - Document why certain rules exist
   - Review settings during code reviews

4. **Test your security boundaries**
   - Regularly verify denied files are truly blocked
   - Test edge cases
   - Update rules as project evolves

## Discussion Questions

1. Why is it important to commit `.claude/settings.json` to version control?
2. What's the difference between deny and allow rules?
3. How do you balance security with developer productivity?
4. What happens if you need Claude to help with environment variable configuration?

## Troubleshooting

**Problem:** Claude can still access denied files
- Solution: Check glob pattern syntax, restart Claude Code

**Problem:** Claude can't access files it should
- Solution: Check allow rules, ensure paths are correct

**Problem:** Settings not taking effect
- Solution: Verify `.claude/settings.json` location, check JSON syntax

## Next Steps

In the next lab, you'll conduct your first AI-assisted code review session using Claude Code with your configured security boundaries.

## Additional Resources

- [Claude Code Documentation](https://docs.claude.com/claude-code)
- [Glob Pattern Cheatsheet](https://github.com/begin/globbing)
- [Security Configuration Examples](https://github.com/anthropics/claude-code-examples)
