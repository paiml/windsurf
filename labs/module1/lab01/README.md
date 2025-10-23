# Lab 1.1: Privacy-Conscious Development Foundations

## Overview

This lab introduces privacy-conscious development principles and demonstrates why protecting sensitive data matters when using AI tools.

## Learning Objectives

By the end of this lab, you will:
- Understand the risks of sharing sensitive data with AI services
- Recognize different types of sensitive data (API keys, credentials, PII, proprietary algorithms)
- Learn about real-world security incidents involving AI tools
- Understand compliance implications (GDPR, CCPA)

## Background

When developers integrate AI tools into their workflow, they focus on productivity but often overlook critical questions about data handling:

- What happens to your API keys when shared with AI services?
- Where is user data stored and who has access?
- Can your proprietary algorithms become training data?

## Key Concepts

### 1. Types of Sensitive Data

**Credentials and API Keys**
- Database passwords
- API keys and tokens
- SSH keys and certificates
- OAuth tokens

**Personal Information (PII)**
- User email addresses
- Phone numbers
- Physical addresses
- Payment information

**Proprietary Information**
- Business logic and algorithms
- Database schemas
- Internal API structures
- Strategic code implementations

### 2. Real-World Example: GitHub Copilot Prompt Injection

**The Attack Vector:**
When a user asks Copilot about GitHub issues, the system fetches issue content and includes it in the AI prompt. Attackers exploited this by creating malicious GitHub issues with hidden instructions.

**What Happened:**
- Malicious GitHub issues contained dangerous instructions embedded in the text
- The AI followed these injected instructions
- Attackers could:
  - Expose GitHub tokens
  - Access sensitive files
  - Execute arbitrary code

**The Lesson:**
This illustrates why security in AI development is an ongoing process. New vulnerabilities emerge as AI capabilities expand, creating risks traditional security measures may not address.

## Hands-On Exercise

### Part 1: Identify Sensitive Data

Review this sample configuration file and identify all sensitive data:

```python
# config.py
DATABASE_URL = "postgresql://admin:SecretPass123@db.company.com:5432/production"
API_KEY = "sk-proj-abc123xyz789"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_KEY = "sk_live_51HqzT..."
USER_EMAIL = "customer@example.com"
INTERNAL_API_ENDPOINT = "https://internal-api.company.com/v2/analytics"
```

**Questions:**
1. What categories of sensitive data are present?
2. What risks does each piece of data pose if exposed?
3. What compliance regulations might apply?

### Part 2: Risk Assessment

For each scenario, identify the risk level (Low/Medium/High/Critical) and explain why:

1. Sharing this code with an AI service for code review:
```python
def calculate_profit_margin(cost, price):
    return (price - cost) / price * 100
```

2. Asking an AI to help optimize this database query:
```sql
SELECT user_id, email, password_hash, credit_card_number
FROM users
WHERE subscription_status = 'active'
```

3. Requesting help to debug this authentication function:
```javascript
function authenticateUser(username, password) {
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    return db.execute(query);
}
```

### Part 3: Privacy-Conscious Alternatives

For the vulnerable authentication function above, rewrite it as a generic example that:
- Demonstrates the same vulnerability pattern
- Uses placeholder variable names
- Removes any production-specific details
- Can be safely shared with an AI service

## Verification

Run the following checks:

```bash
# Check if you've identified all sensitive data types
echo "Did you identify:"
echo "- Database credentials"
echo "- API keys"
echo "- Cloud provider keys"
echo "- Payment processor keys"
echo "- PII (email addresses)"
echo "- Internal API endpoints"
```

## Discussion Questions

1. How does sharing proprietary algorithms differ from sharing credentials in terms of risk?
2. Why are regulations like GDPR and CCPA relevant to AI tool usage?
3. What is "prompt injection" and how does it relate to AI security?
4. How can you balance productivity gains from AI tools with security concerns?

## Additional Resources

- OWASP AI Security and Privacy Guide
- GDPR Guidelines for Software Development
- CCPA Compliance Checklist
- GitHub Security Best Practices

## Next Steps

In the next lab, you'll learn about different AI tool architectures (web-based vs CLI-based) and their security implications.
