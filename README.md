[![Banner](./.github/header.svg)](https://ds500.paiml.com/ "Pragmatic AI Labs")

<h1 align="center">Windsurf for Privacy Conscious Development</h1>
<h5 align="center">Using AI Development Tools Securely Without Exposing Sensitive Data</h3>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#learning-objectives">Learning Objectives</a> •
  <a href="#course-modules">Course Modules</a> •
  <a href="#labs">Labs</a> •
  <a href="#getting-started">Getting Started</a>
</p>

## Overview

Learn to use AI-powered development tools like Windsurf, Claude Code, and Gemini CLI while protecting sensitive data, credentials, and proprietary information. This course teaches you secure prompting techniques, privacy-conscious workflows, and how to identify and fix security vulnerabilities without exposing your production systems.

## Learning Objectives

By the end of this course, you will be able to:

* Understand privacy risks when using AI development tools
* Configure AI tools with security-first settings
* Use secure prompting techniques to protect sensitive data
* Identify and fix security vulnerabilities (SQL injection, file uploads, etc.)
* Implement automated security scanning with local tools
* Set up GitHub Advanced Security and Dependabot
* Make informed decisions about AI tool usage in production environments

## Course Structure

### Module 1: Privacy-Conscious Development Foundations

**1.1 Understanding Privacy Risks**
- What happens to your data when you use AI services
- Types of sensitive data (credentials, PII, proprietary code)
- Real-world incidents (GitHub Copilot prompt injection)
- Compliance implications (GDPR, CCPA)

**1.2 Claude Code Setup and Security**
- Installing Claude Code CLI
- Configuring `.claude/settings.json` for file access control
- Testing security boundaries
- Version controlling security policies

**1.3 Windsurf IDE for Secure Development**
- Installing and configuring Windsurf
- Using Cascade AI for security scanning
- AI-assisted code refactoring
- Multi-model security analysis

**1.4 Secure Prompting Principles**
- Pattern-based vs. specific code queries
- Code sanitization techniques
- Progressive disclosure strategies
- Defense-in-depth approaches

### Module 2: Security Vulnerabilities and Prevention

**2.1 SQL Injection Prevention**
- Understanding SQL injection attacks
- Using AI to analyze vulnerability patterns
- Implementing parameterized queries
- Input validation and security testing

**2.2 Secure File Handling**
- File upload vulnerabilities
- Path traversal prevention
- MIME type validation
- Secure file storage patterns

**2.3 HTTP Security Headers and Container Scanning**
- Essential security headers (CSP, HSTS, etc.)
- CORS configuration
- Local container scanning with Grype
- Privacy-conscious security testing

**2.4 GitHub Advanced Security**
- Dependabot for dependency updates
- CodeQL code scanning
- Secret scanning and push protection
- Automated security workflows

## Labs

Complete hands-on labs for each module:

* **[Lab 1.1: Privacy-Conscious Development Foundations](labs/module1/lab01/README.md)**
* **[Lab 1.2: Setting Up Claude Code](labs/module1/lab02/README.md)**
* **[Lab 1.3: Setting Up Windsurf IDE](labs/module1/lab03/README.md)**
* **[Lab 1.4: Secure Prompting and AI Tool Safety](labs/module1/lab04/README.md)**
* **[Lab 2.1: SQL Injection Prevention](labs/module2/lab01/README.md)**
* **[Lab 2.2: Secure File Handling](labs/module2/lab02/README.md)**
* **[Lab 2.3: HTTP Security Headers and Container Scanning](labs/module2/lab03/README.md)**
* **[Lab 2.4: GitHub Advanced Security](labs/module2/lab04/README.md)**

See the [complete labs guide](labs/README.md) for detailed instructions.

## Key Principles

### 1. Never Share Production Secrets
- Don't paste API keys, passwords, or tokens into AI tools
- Use environment variables in examples
- Sanitize code before requesting AI assistance

### 2. Pattern-Based Queries
❌ **Bad**: "Review my auth code: [paste production code with DB credentials]"

✅ **Good**: "What security issues exist in this authentication pattern:
```sql
SELECT * FROM users WHERE username='USER_INPUT' AND password='USER_INPUT'
```"

### 3. Configure Tool Permissions
```json
{
  "permissions": {
    "deny": [".env", "secrets/**", "**/*.key"],
    "allow": ["src/**", "tests/**", "docs/**"]
  }
}
```

### 4. Defense in Depth
- Tool configuration (deny lists, permissions)
- Prompting discipline (sanitize, use patterns)
- Code review (human verification)
- Automated scanning (Grype, CodeQL, Dependabot)
- Monitoring (track what's shared)

## Required Tools

### AI Development Tools (Choose One or More)
- **[Windsurf](https://windsurf.com)** - AI-powered IDE with Cascade AI
- **[Claude Code](https://www.anthropic.com/claude-code)** - CLI with strong privacy features
- **[Gemini CLI](https://github.com/google-gemini/gemini-cli)** - Google's CLI tool

### Security Tools
- **[Grype](https://github.com/anchore/grype)** - Local container vulnerability scanning
- **Git** - Version control
- **Docker** - For container scanning labs
- **Node.js 18+** or **Python 3.8+** - For code examples

### Optional but Recommended
- GitHub account (for GHAS labs)
- VS Code or preferred IDE
- Browser DevTools

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/paiml/windsurf.git
cd windsurf
```

### 2. Choose Your AI Tool

**Option A: Windsurf (Recommended)**
```bash
# Download from https://windsurf.com
# Install for your platform
# Open and sign in
```

**Option B: Claude Code**
```bash
npm install -g claude-code
claude --version
```

**Option C: Gemini CLI**
```bash
npm install -g @google/generative-ai-cli
# Configure API key
```

### 3. Start with Module 1, Lab 1
```bash
cd labs
cat module1/lab01/README.md
```

## What You'll Build

By completing this course, you will:

- ✅ Configure AI tools with security-first settings
- ✅ Master secure prompting techniques
- ✅ Identify and fix SQL injection vulnerabilities
- ✅ Implement secure file upload handling
- ✅ Configure HTTP security headers
- ✅ Scan containers locally with Grype
- ✅ Set up automated security workflows with GitHub
- ✅ Make informed decisions about AI tool usage

## Course Completion

After finishing all labs, you will be able to:

1. Use AI tools securely without exposing sensitive data
2. Apply secure prompting patterns effectively
3. Identify common vulnerabilities (SQL injection, file upload, XSS, etc.)
4. Implement automated security scanning
5. Train others on privacy-conscious development practices

## Resources

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)

### AI Tool Documentation
- [Windsurf Documentation](https://docs.windsurf.com)
- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [Gemini CLI Documentation](https://github.com/google-gemini/gemini-cli)

### Security Tools
- [Grype Documentation](https://github.com/anchore/grype)
- [GitHub Advanced Security](https://docs.github.com/en/code-security)
- [Dependabot](https://docs.github.com/en/code-security/dependabot)
- [CodeQL](https://codeql.github.com/docs/)

## Contributing

Found an issue or have an improvement?

1. **Report Issues**: [GitHub Issues](https://github.com/paiml/windsurf/issues)
2. **Suggest Improvements**: Pull requests welcome
3. **Share Feedback**: What worked? What didn't?

## License

MIT License - See [LICENSE](LICENSE) for details

## Acknowledgments

- **Course Author**: Liam Parker ([paiml.com](https://paiml.com))
- **Organization**: Pragmatic AI Labs (PAIML)
- **Platform**: [LinkedIn Learning](https://www.linkedin.com/learning/)
- **Tools**: Windsurf, Claude (Anthropic), Gemini (Google)
- **Quality Standards**: [pmat](https://github.com/paiml/paiml-mcp-agent-toolkit)

---

**Ready to start?** Jump into [Module 1, Lab 1](labs/module1/lab01/README.md) and learn about privacy-conscious development! 🔒
