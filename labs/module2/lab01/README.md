# Lab 2.1: SQL Injection Prevention with AI-Assisted Security Analysis

## Overview

This lab teaches you to identify, understand, and fix SQL injection vulnerabilities using AI tools and secure prompting techniques.

## Learning Objectives

By the end of this lab, you will:
- Understand SQL injection attack vectors
- Use AI to identify SQL injection vulnerabilities without exposing production code
- Learn secure coding patterns (parameterized queries)
- Implement authentication systems resistant to SQL injection
- Apply pattern-based learning for lasting security knowledge

## Prerequisites

- Completed Module 1 labs
- Basic understanding of SQL and databases
- Access to an AI tool (Claude Code, Windsurf, or similar)
- Understanding of secure prompting principles

## Part 1: Understanding SQL Injection

### What is SQL Injection?

SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization, allowing attackers to manipulate query logic.

### Common Vulnerable Pattern

```sql
SELECT * FROM users WHERE username='USER_INPUT' AND password='USER_INPUT'
```

When user input is directly substituted:

```sql
-- Normal input
SELECT * FROM users WHERE username='john' AND password='secret123'

-- Malicious input: username = "admin'--"
SELECT * FROM users WHERE username='admin'--' AND password='secret123'
-- The -- comments out the password check!

-- Malicious input: username = "' OR '1'='1"
SELECT * FROM users WHERE username='' OR '1'='1' AND password='secret123'
-- This query always returns true!
```

## Part 2: Hands-On Vulnerability Analysis

### Exercise 1: Identify SQL Injection Vulnerabilities

Analyze this vulnerable login implementation:

```javascript
// VULNERABLE CODE - DO NOT USE
const express = require('express');
const mysql = require('mysql');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'dbuser',
    password: 'dbpass',
    database: 'myapp'
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // VULNERABILITY: Direct string concatenation
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    connection.query(query, (error, results) => {
        if (error) {
            res.status(500).json({ error: error.message });
            return;
        }

        if (results.length > 0) {
            res.json({ success: true, user: results[0] });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    });
});
```

**Your Task:**
1. Identify all security issues
2. List potential attack vectors
3. Assess the impact of each vulnerability

**Security Issues:**
- **SQL Injection**: User input directly in query string
- **Information Disclosure**: Error messages expose database details
- **No Input Validation**: Accepts any input format
- **Plain-text Password**: No password hashing
- **Over-disclosure**: Returns entire user object

## Part 3: Secure Prompting for SQL Security

### Exercise 2: Create Safe AI Queries

**❌ Bad Prompt (Exposes Details):**
```
Review my authentication code:
[Paste production code with database connection, table names, etc.]
```

**✅ Good Prompt (Pattern-Based):**
```
What's wrong with this database query pattern for user authentication?

SELECT * FROM users WHERE username='USER_INPUT' AND password='USER_INPUT'

Please explain:
1. SQL injection vulnerabilities
2. How attackers could exploit this
3. Secure alternatives
```

### Exercise 3: Query AI About SQL Injection

Open your AI tool and use this prompt:

```
I'm reviewing a generic database query pattern for security issues:

Pattern:
SELECT * FROM users WHERE username='USER_INPUT' AND password='USER_INPUT'

Questions:
1. What SQL injection attacks are possible?
2. What are example malicious inputs?
3. What is the impact of successful exploitation?
4. What are the best practices to prevent this?
```

**Document the AI Response:**
- What vulnerabilities did it identify?
- What attack examples did it provide?
- What solutions did it recommend?

## Part 4: Implementing Secure Solutions

### Exercise 4: Fix with Parameterized Queries

#### Option 1: Node.js with MySQL

```javascript
// SECURE VERSION
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
    connectionLimit: 10
});

app.post('/login', [
    // Input validation middleware
    body('username')
        .isAlphanumeric()
        .trim()
        .isLength({ min: 3, max: 30 })
        .escape(),
    body('password')
        .isLength({ min: 8 })
], async (req, res) => {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
        // SECURE: Parameterized query with placeholders
        const [rows] = await pool.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            [username]
        );

        if (rows.length === 0) {
            // Generic error message
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = rows[0];

        // Compare hashed password
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            // Return only necessary data
            res.json({
                success: true,
                userId: user.id,
                username: user.username
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
    } catch (error) {
        // Log error server-side only
        console.error('Login error:', error);

        // Generic client response
        res.status(500).json({
            error: 'An error occurred. Please try again.'
        });
    }
});
```

#### Option 2: Python with PostgreSQL

```python
# SECURE VERSION
from flask import Flask, request, jsonify
import psycopg2
from psycopg2 import pool
import bcrypt
import os
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)

# Connection pool with environment variables
connection_pool = psycopg2.pool.SimpleConnectionPool(
    1, 20,
    host=os.getenv('DB_HOST'),
    database=os.getenv('DB_NAME'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD')
)

# Input validation schema
class LoginSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: 3 <= len(x) <= 30)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 8)

login_schema = LoginSchema()

@app.route('/login', methods=['POST'])
def login():
    # Validate input
    try:
        data = login_schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

    username = data['username']
    password = data['password']

    conn = connection_pool.getconn()
    try:
        with conn.cursor() as cursor:
            # SECURE: Parameterized query with %s placeholders
            cursor.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,)
            )

            user = cursor.fetchone()

            if user is None:
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials'
                }), 401

            user_id, username, password_hash = user

            # Verify password hash
            if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                return jsonify({
                    'success': True,
                    'userId': user_id,
                    'username': username
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials'
                }), 401

    except Exception as e:
        # Log error server-side
        app.logger.error(f'Login error: {e}')

        # Generic client response
        return jsonify({
            'error': 'An error occurred. Please try again.'
        }), 500

    finally:
        connection_pool.putconn(conn)
```

## Part 5: Additional SQL Injection Scenarios

### Exercise 5: Secure Different Query Types

#### Scenario 1: Dynamic Search Queries

**Vulnerable:**
```javascript
app.get('/search', (req, res) => {
    const { term } = req.query;
    const query = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});
```

**Secure:**
```javascript
app.get('/search', [
    query('term').trim().escape().isLength({ max: 100 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { term } = req.query;

    try {
        const [rows] = await pool.execute(
            'SELECT id, name, description, price FROM products WHERE name LIKE ?',
            [`%${term}%`]
        );
        res.json(rows);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});
```

#### Scenario 2: Dynamic Sorting

**Vulnerable:**
```python
@app.route('/users')
def get_users():
    sort_by = request.args.get('sort', 'id')
    query = f"SELECT * FROM users ORDER BY {sort_by}"
    # SQL injection via sort parameter!
    cursor.execute(query)
    return jsonify(cursor.fetchall())
```

**Secure:**
```python
@app.route('/users')
def get_users():
    sort_by = request.args.get('sort', 'id')

    # Whitelist allowed columns
    allowed_columns = ['id', 'username', 'created_at', 'email']

    if sort_by not in allowed_columns:
        return jsonify({'error': 'Invalid sort column'}), 400

    # Safe to use since validated against whitelist
    query = f"SELECT id, username, created_at FROM users ORDER BY {sort_by}"

    cursor.execute(query)
    return jsonify(cursor.fetchall())
```

## Part 6: Testing for SQL Injection

### Exercise 6: Manual Testing

Test your implementation with these payloads:

```
# Common SQL injection payloads
' OR '1'='1
' OR 1=1--
admin'--
admin' /*
admin'#
' or 'x'='x
') or ('x'='x
' or 1=1--
" or 1=1--
or 1=1--
' or 'a'='a
" or "a"="a
') or ('a'='a
") or ("a"="a
```

**Your Task:**
1. Try these payloads against your secure implementation
2. Verify all are properly handled
3. Check error messages don't reveal system details

### Exercise 7: Use AI for Pattern Learning

Create this prompt for your AI tool:

```
Teach me about SQL injection by explaining these attack patterns:

1. Comment-based bypass (admin'--)
2. Boolean-based blind SQL injection
3. Union-based SQL injection
4. Time-based blind SQL injection

For each:
- Explain the technique
- Show an example payload
- Explain how parameterized queries prevent it
```

## Verification Checklist

- [ ] Understand how SQL injection works
- [ ] Can identify vulnerable query patterns
- [ ] Used secure prompting with AI tools
- [ ] Implemented parameterized queries
- [ ] Added input validation
- [ ] Implemented password hashing
- [ ] Tested with common attack payloads
- [ ] Verified error messages are generic

## Security Best Practices

1. **Always use parameterized queries**
   - Never concatenate user input into SQL
   - Use ? or %s placeholders

2. **Validate all input**
   - Type checking
   - Length limits
   - Format validation
   - Whitelist allowed values

3. **Use prepared statements**
   - Most databases support them
   - Separate SQL logic from data

4. **Principle of Least Privilege**
   - Database users should have minimum necessary permissions
   - Read-only where possible

5. **Error handling**
   - Log errors server-side
   - Return generic messages to clients
   - Don't expose database structure

## Discussion Questions

1. Why do parameterized queries prevent SQL injection?
2. Is input validation sufficient without parameterized queries?
3. What's the difference between client-side and server-side validation?
4. Can stored procedures be vulnerable to SQL injection?
5. How does asking about patterns vs. specific code improve security learning?

## Additional Challenges

1. **Challenge 1:** Secure a bulk update endpoint
2. **Challenge 2:** Implement secure full-text search
3. **Challenge 3:** Create a query builder with SQL injection protection
4. **Challenge 4:** Write tests that verify SQL injection prevention

## Next Steps

In the next lab, you'll learn about secure file handling, including path traversal vulnerabilities and how to safely process user-uploaded files.

## Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Bobby Tables (XKCD)](https://xkcd.com/327/)
- [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
