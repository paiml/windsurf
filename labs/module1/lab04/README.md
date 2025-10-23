# Lab 1.4: Secure Prompting and AI Tool Safety

## Overview

This lab teaches you how to interact safely with AI tools, write security-conscious prompts, and protect sensitive information while leveraging AI capabilities.

## Learning Objectives

By the end of this lab, you will:
- Understand secure prompting principles
- Learn to sanitize code before sharing with AI
- Master pattern-based vs. specific code queries
- Configure AI tools for maximum privacy
- Implement defense-in-depth strategies

## Prerequisites

- Completed Labs 1.1-1.3
- Access to at least one AI tool (Claude Code, Windsurf, or Gemini CLI)
- Understanding of basic security concepts

## Part 1: Secure Prompting Principles

### Principle 1: Ask About Patterns, Not Specifics

**Bad Example (Exposes Details):**
```
Review my authentication code:

function authenticateUser(username, password) {
    const query = `SELECT * FROM customer_accounts WHERE email='${username}' AND password='${password}'`;
    return companyDB.execute(query);
}

Our customer_accounts table has columns: id, email, password, credit_card_hash, ssn_encrypted, billing_address
```

**Good Example (Pattern-Based):**
```
What's wrong with this database query pattern for user authentication?

SELECT * FROM users WHERE username='USER_INPUT' AND password='USER_INPUT'

Focus on security vulnerabilities in the query structure.
```

### Principle 2: Sanitize Before Sharing

**Original Production Code:**
```python
# payment_processor.py
import stripe
stripe.api_key = "EXAMPLE_STRIPE_API_KEY_DO_NOT_USE"

def process_payment(customer_id, amount):
    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        customer=customer_id,
        description=f"Payment from {customer_id}"
    )
    return charge.id
```

**Sanitized Version for AI:**
```python
# Generic payment processing pattern
import payment_provider

payment_provider.api_key = "PAYMENT_API_KEY"

def process_transaction(customer_id, amount):
    transaction = payment_provider.Charge.create(
        amount=amount,
        currency="usd",
        customer=customer_id,
        description=f"Transaction for {customer_id}"
    )
    return transaction.id
```

## Part 2: Practical Exercises

### Exercise 1: Sanitize and Query

Given this production code, sanitize it and create a safe prompt:

```javascript
// Production code - DO NOT SHARE AS-IS
const AWS = require('aws-sdk');
const s3 = new AWS.S3({
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1'
});

async function uploadCustomerData(customerId, data) {
    const params = {
        Bucket: 'acme-corp-customer-pii',
        Key: `customers/${customerId}/profile.json`,
        Body: JSON.stringify(data),
        ContentType: 'application/json'
    };

    const result = await s3.putObject(params).promise();
    console.log(`Uploaded to ${params.Bucket}/${params.Key}`);
    return result.ETag;
}
```

**Your Task:**
1. Identify all sensitive information
2. Create a sanitized version
3. Write a secure prompt to ask about cloud storage best practices

**Solution:**

Sanitized code:
```javascript
// Cloud storage pattern
const CloudStorage = require('cloud-storage-sdk');
const storage = new CloudStorage({
    credentials: process.env.CLOUD_CREDENTIALS,
    region: process.env.CLOUD_REGION
});

async function uploadData(dataId, data) {
    const params = {
        Bucket: process.env.STORAGE_BUCKET,
        Key: `data/${dataId}/file.json`,
        Body: JSON.stringify(data),
        ContentType: 'application/json'
    };

    const result = await storage.putObject(params).promise();
    return result.ETag;
}
```

Secure prompt:
```
I'm using a cloud storage SDK to upload JSON data. What security best practices should I follow for:
1. Credential management
2. Data encryption
3. Access control
4. Error handling
5. Logging
```

### Exercise 2: Pattern Recognition vs. Code Review

**Scenario A: Direct Code Review (RISKY)**
```
Review this code from our payment gateway:
[Paste entire payment processing module with API keys, business logic, customer data structures]
```

**Scenario B: Pattern-Based Query (SAFE)**
```
What are common security vulnerabilities in payment processing code? Consider:
- API key management
- Data validation
- Transaction logging
- Error handling
- PCI DSS compliance
```

**Your Task:**
Write pattern-based queries for these scenarios:
1. Authentication system with JWT tokens
2. File upload functionality
3. Database migration scripts
4. API rate limiting

## Part 3: AI Tool Safety Configuration

### Exercise 3: Configure Gemini CLI for Privacy

Install and configure Gemini CLI with privacy settings:

```bash
# Install Gemini CLI
npm install -g @google/generative-ai-cli

# Configure with minimal permissions
gemini config set --privacy-mode strict
gemini config set --data-retention none
gemini config set --telemetry false
```

Create a `.gemini-config.json`:

```json
{
  "model": "gemini-pro",
  "temperature": 0.7,
  "privacy": {
    "redact_emails": true,
    "redact_urls": true,
    "redact_ip_addresses": true,
    "local_mode": true
  },
  "safety": {
    "block_none": false,
    "har_block_threshold": "BLOCK_MEDIUM_AND_ABOVE"
  },
  "context": {
    "max_history": 0,
    "save_conversations": false
  }
}
```

### Exercise 4: Create a Secure Prompting Checklist

Create a checklist file: `secure-prompting-checklist.md`

```markdown
# Secure Prompting Checklist

Before sharing code with an AI tool, verify:

## Credentials and Secrets
- [ ] No API keys
- [ ] No passwords
- [ ] No tokens or certificates
- [ ] No connection strings with credentials

## Personal Information
- [ ] No real email addresses
- [ ] No phone numbers
- [ ] No physical addresses
- [ ] No names (customers or employees)

## Proprietary Information
- [ ] No company-specific business logic
- [ ] No internal API endpoints
- [ ] No database schemas
- [ ] No infrastructure details

## Safe Alternatives Used
- [ ] Environment variables referenced
- [ ] Placeholder names used
- [ ] Generic patterns demonstrated
- [ ] Focus on security concepts, not specifics

## Query Quality
- [ ] Question focuses on patterns
- [ ] Provides enough context for AI
- [ ] Doesn't over-share
- [ ] Has clear security objective
```

## Part 4: Advanced Secure Prompting Techniques

### Technique 1: Progressive Disclosure

Start general, get specific only if needed:

**Step 1 (General):**
```
What are SQL injection risks in user authentication?
```

**Step 2 (More Specific if needed):**
```
How do I safely parameterize this query pattern:
SELECT * FROM users WHERE username = ? AND password = ?
```

**Step 3 (Implementation Guidance):**
```
Show me how to use parameterized queries in [language] with [database]
```

### Technique 2: Hypothetical Scenarios

Frame questions as educational hypotheticals:

```
If a developer were building an authentication system and made these common mistakes:
1. String concatenation in SQL queries
2. Storing passwords in plain text
3. No rate limiting on login attempts

What would be the security implications and how should they fix each issue?
```

### Technique 3: Reverse Engineering Safe Examples

```
Here's a secure implementation of [feature]. Can you explain:
1. What security principles it follows
2. What vulnerabilities it prevents
3. What additional improvements could be made

[Paste sanitized, security-hardened code example]
```

## Part 5: Hands-On Security Audit

### Exercise 5: Complete Workflow

1. Take this vulnerable code:

```python
# api_server.py
from flask import Flask, request
import os

app = Flask(__name__)
SECRET_KEY = "hardcoded_secret_key_12345"
DB_URL = "postgresql://admin:password@db.company.com/prod"

@app.route('/api/user/<user_id>')
def get_user(user_id):
    # Direct string interpolation - SQL injection!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = execute_query(query)
    return result

@app.route('/api/files/<filename>')
def get_file(filename):
    # Path traversal vulnerability!
    filepath = f"/var/data/{filename}"
    with open(filepath, 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production!
```

2. Sanitize it
3. Create a secure prompt
4. Query your AI tool
5. Implement fixes
6. Verify security

**Deliverables:**
- Sanitized code version
- Your secure prompt
- AI recommendations (summary)
- Fixed code with security controls

## Verification and Testing

### Test Your Understanding

Create secure prompts for these scenarios:

1. **Scenario:** You have a race condition in concurrent database writes
   - **Your Secure Prompt:** ___________

2. **Scenario:** Your OAuth implementation seems flawed
   - **Your Secure Prompt:** ___________

3. **Scenario:** File uploads aren't properly validated
   - **Your Secure Prompt:** ___________

### Self-Assessment Quiz

1. What's the main difference between pattern-based and specific code queries?
2. Why is sanitizing code before sharing important even with trusted AI tools?
3. Name three types of sensitive data to always remove
4. How does progressive disclosure help maintain privacy?
5. What should you do if an AI tool asks for more details about your production system?

## Best Practices Summary

### ✅ DO
- Ask about patterns and concepts
- Sanitize all code before sharing
- Use placeholder names
- Focus on security principles
- Provide sufficient context
- Use environment variables in examples
- Review AI suggestions critically

### ❌ DON'T
- Share production credentials
- Include real user data
- Expose database schemas
- Share internal API endpoints
- Paste code with company-specific logic
- Trust AI output blindly
- Share connection strings

## Defense in Depth

Implement multiple layers of protection:

1. **Tool Configuration**: Use privacy settings
2. **Prompting Discipline**: Follow secure prompting guidelines
3. **Code Sanitization**: Remove sensitive data
4. **Review Process**: Human verification of AI suggestions
5. **Access Controls**: Limit AI tool permissions
6. **Monitoring**: Track what gets shared with AI tools

## Discussion Questions

1. Can you ever truly sanitize proprietary business logic?
2. What's the trade-off between security and AI utility?
3. How do you balance team productivity with security concerns?
4. Should companies ban AI tools or teach safe usage?
5. What happens when an AI tool's privacy policy changes?

## Real-World Incident Analysis

**Case Study: Data Leak via AI Tool**

A developer pasted database migration scripts into an AI chat tool. The scripts contained:
- Production database schema
- Column names revealing sensitive data types
- Business logic in SQL triggers
- Performance optimization hints (table sizes)

**Impact:**
- Competitive intelligence leaked
- Attack surface revealed
- Regulatory violation (GDPR)

**Lesson:**
Even seemingly innocuous technical details can reveal sensitive information. Always sanitize.

## Next Steps

In Module 2, you'll apply these secure prompting techniques to identify and fix real-world vulnerabilities including SQL injection, file handling issues, and HTTP header security problems.

## Additional Resources

- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [Prompt Injection Attack Examples](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)
- [Anthropic's Claude Security Best Practices](https://docs.anthropic.com/claude/docs/security)
- [Google's AI Principles](https://ai.google/principles/)
- [Microsoft's Responsible AI Standards](https://www.microsoft.com/en-us/ai/responsible-ai)
