# Lab 1.3: Setting Up Windsurf IDE for Secure AI-Assisted Development

## Overview

This lab walks through installing and using Windsurf, an AI-powered IDE that integrates multiple AI models for code review and security analysis.

## Learning Objectives

By the end of this lab, you will:
- Install and configure Windsurf IDE
- Understand Windsurf's AI features (Cascade Code)
- Perform security vulnerability scanning
- Use AI to refactor insecure code
- Configure security rules and workflows

## Prerequisites

- Windows, macOS, or Linux system
- Windsurf account (free tier available)
- Basic understanding of web development
- Familiarity with VS Code (helpful but not required)

## Part 1: Installation and Setup

### Step 1: Download and Install Windsurf

1. Visit [https://windsurf.com](https://windsurf.com)
2. Click "Download for [Your OS]"
   - Windows: Download `.exe` installer
   - macOS: Download `.dmg` file
   - Linux: Download `.deb` or `.AppImage`

3. Install Windsurf:
```bash
# Linux example
sudo dpkg -i windsurf_*.deb

# Or using AppImage
chmod +x Windsurf-*.AppImage
./Windsurf-*.AppImage
```

### Step 2: Initial Onboarding

1. Launch Windsurf
2. Click "Get Started"
3. Choose import options:
   - **Import from VS Code**: Brings extensions and settings
   - **Start Fresh**: Clean installation
4. Select your preferred theme
5. Create a Windsurf account or log in

### Step 3: Explore the Interface

**Key Features:**
- **Cascade Code**: Windsurf's AI assistant
- **Multiple AI Models**: GPT-4.5, Claude Sonnet 4, Gemini, and more
- **Agent Mode**: Autonomous AI coding vs. chat mode
- **Image Upload**: Visual context for AI
- **Rules & Workflows**: Custom AI behavior
- **Memory**: Context retention across sessions

## Part 2: Security Scanning with Windsurf

### Exercise 1: Scan Vulnerable Code

Create a test file with security vulnerabilities:

```bash
mkdir windsurf-security-lab
cd windsurf-security-lab
```

Create `vulnerable-auth.js`:

```javascript
// vulnerable-auth.js - DO NOT USE IN PRODUCTION
const express = require('express');
const mysql = require('mysql');

// SECURITY ISSUE: Hard-coded credentials
const DB_HOST = 'localhost';
const DB_USER = 'admin';
const DB_PASSWORD = 'SuperSecret123!';
const DB_NAME = 'userdb';

const app = express();
app.use(express.json());

// SECURITY ISSUE: SQL Injection vulnerability
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // DANGER: User input directly in query
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    connection.query(query, (error, results) => {
        if (error) {
            // SECURITY ISSUE: Information disclosure
            res.status(500).json({ error: error.message });
            return;
        }

        if (results.length > 0) {
            res.json({ success: true, user: results[0] });
        } else {
            res.json({ success: false });
        }
    });
});

// SECURITY ISSUE: Missing input validation
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const query = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;

    connection.query(query, (error, results) => {
        if (error) {
            res.status(500).json({ error: error.message });
            return;
        }
        res.json({ success: true, userId: results.insertId });
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

### Step 4: Use Windsurf AI for Security Analysis

1. Open the file in Windsurf
2. Open Cascade Code (AI panel)
3. Select your preferred model (e.g., Claude Sonnet 4)
4. Enter this prompt:

```
Can you scan this code for security vulnerabilities? Please identify:
1. Hard-coded credentials
2. SQL injection risks
3. Information disclosure issues
4. Missing input validation
5. Any other security concerns
```

### Step 5: Review AI Response

Windsurf will identify issues like:

**1. Hard-coded Credentials**
- Risk: Credentials exposed in source code
- Impact: Database compromise if code is leaked

**2. SQL Injection Vulnerability**
- Risk: Attacker can manipulate queries
- Impact: Data breach, unauthorized access

**3. Information Disclosure**
- Risk: Error messages reveal system details
- Impact: Helps attackers understand infrastructure

**4. Missing Input Validation**
- Risk: Malformed data can cause crashes
- Impact: Denial of service, data corruption

## Part 3: AI-Assisted Security Remediation

### Exercise 2: Refactor with Windsurf AI

Prompt Windsurf to fix the vulnerabilities:

```
Please refactor this code to fix all security issues:
1. Use environment variables for credentials
2. Use parameterized queries to prevent SQL injection
3. Add proper input validation
4. Implement secure error handling
5. Add password hashing
```

Windsurf will:
1. Create a todo list of tasks
2. Show step-by-step progress
3. Create an `.env.example` file
4. Update code with security fixes
5. Add a `.gitignore` file
6. Provide usage instructions

### Expected Secure Implementation

```javascript
// secure-auth.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const app = express();
app.use(express.json());

// Secure login with parameterized queries
app.post('/login', [
    body('username').isAlphanumeric().trim().isLength({ min: 3, max: 30 }),
    body('password').isLength({ min: 8 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            res.json({ success: true, userId: user.id });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'An error occurred during login' });
    }
});

// Secure registration
app.post('/register', [
    body('username').isAlphanumeric().trim().isLength({ min: 3, max: 30 }),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[A-Za-z])(?=.*\d)/)
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        res.status(201).json({ success: true, userId: result.insertId });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(409).json({ error: 'Username or email already exists' });
        } else {
            res.status(500).json({ error: 'An error occurred during registration' });
        }
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

## Part 4: Configure Windsurf Security Rules

### Exercise 3: Create Security Workflows

1. In Windsurf, open Settings → Rules & Workflows
2. Create a custom rule for security reviews:

```yaml
name: Security Review
trigger: on_file_open
conditions:
  - file_extension: [.js, .ts, .py, .java]
actions:
  - check_for_patterns:
      - hard_coded_credentials
      - sql_injection
      - command_injection
      - path_traversal
  - suggest_fixes: true
```

### Exercise 4: Configure Memory and Context

Configure what Windsurf should remember:
- Security preferences
- Coding standards
- Previously identified vulnerabilities
- Preferred security libraries

## Part 5: Advanced Features

### Multi-Model Comparison

Try the same security scan with different models:

1. **Claude Sonnet 4**: Detailed explanations, comprehensive fixes
2. **GPT-4.5**: Fast responses, good for quick checks
3. **Gemini**: Balance of speed and detail

**Prompt:**
```
Compare the security vulnerabilities in this code and rank them by severity. Provide OWASP Top 10 classification for each issue.
```

### Agent Mode

Enable Agent Mode for autonomous security fixes:
1. Switch to "Agent" mode in Cascade Code
2. Provide high-level instruction: "Make this code production-ready with enterprise security standards"
3. Watch as Windsurf autonomously:
   - Identifies issues
   - Creates a remediation plan
   - Implements fixes
   - Adds tests
   - Updates documentation

## Verification Checklist

- [ ] Windsurf IDE is installed and configured
- [ ] Can scan code for security vulnerabilities
- [ ] Understand AI-generated security recommendations
- [ ] Successfully refactored vulnerable code
- [ ] Created `.env.example` and `.gitignore`
- [ ] Configured security rules/workflows
- [ ] Tested multiple AI models

## Security Best Practices with Windsurf

1. **Never paste production credentials**
   - Always use example/placeholder values
   - Use environment variables

2. **Review AI suggestions carefully**
   - AI can miss context-specific issues
   - Verify all security fixes

3. **Use sanitized examples**
   - Modify real code before sharing
   - Remove company-specific details

4. **Leverage multiple models**
   - Different AI models catch different issues
   - Cross-validate security recommendations

## Discussion Questions

1. How does Windsurf's multi-model approach benefit security analysis?
2. What are the risks of blindly accepting AI-generated security fixes?
3. How can Agent Mode be used safely in security-critical contexts?
4. What types of vulnerabilities are AI tools best at identifying?

## Next Steps

In the next lab, you'll explore additional CLI-based AI tools like Gemini CLI and learn techniques for using AI tools safely across different platforms.

## Additional Resources

- [Windsurf Documentation](https://docs.windsurf.com)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
