# Lab 2.3: HTTP Security Headers and Container Scanning

## Overview

This lab covers HTTP security headers (CSP, CORS, HSTS, etc.) and introduces Grype for local container vulnerability scanning.

## Learning Objectives

By the end of this lab, you will:
- Understand essential HTTP security headers
- Implement Content Security Policy (CSP)
- Configure CORS securely
- Use Grype for container vulnerability scanning
- Perform privacy-conscious security testing

## Prerequisites

- Completed previous Module 2 labs
- Docker installed
- Basic understanding of HTTP
- Command-line proficiency

## Part 1: HTTP Security Headers

### Essential Security Headers

#### 1. Content Security Policy (CSP)
Prevents XSS by controlling resource loading.

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

#### 2. Strict-Transport-Security (HSTS)
Forces HTTPS connections.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

#### 3. X-Content-Type-Options
Prevents MIME type sniffing.

```
X-Content-Type-Options: nosniff
```

#### 4. X-Frame-Options
Prevents clickjacking.

```
X-Frame-Options: DENY
```

#### 5. X-XSS-Protection
Browser XSS filter (legacy, but still useful).

```
X-XSS-Protection: 1; mode=block
```

#### 6. Referrer-Policy
Controls referrer information.

```
Referrer-Policy: strict-origin-when-cross-origin
```

### Exercise 1: Implement Security Headers

#### Node.js/Express Implementation

```javascript
// security-headers.js
const express = require('express');
const helmet = require('helmet');

const app = express();

// Use Helmet for common security headers
app.use(helmet());

// Custom CSP configuration
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "cdn.example.com"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "api.example.com"],
        fontSrc: ["'self'", "fonts.googleapis.com"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
    },
}));

// HSTS Header
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));

// Additional custom headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const whitelist = ['https://example.com', 'https://app.example.com'];

        if (!origin || whitelist.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

const cors = require('cors');
app.use(cors(corsOptions));

// Sample route
app.get('/', (req, res) => {
    res.send('Hello with security headers!');
});

app.listen(3000, () => {
    console.log('Server with security headers running on port 3000');
});
```

#### Python/Flask Implementation

```python
# security_headers.py
from flask import Flask, make_response
from flask_cors import CORS
from flask_talisman import Talisman

app = Flask(__name__)

# Configure Talisman for security headers
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", 'cdn.example.com'],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'connect-src': ["'self'", 'api.example.com'],
    'font-src': ["'self'", 'fonts.googleapis.com'],
    'object-src': "'none'",
    'media-src': "'self'",
    'frame-src': "'none'",
}

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    }
)

# CORS configuration
CORS(app, origins=['https://example.com', 'https://app.example.com'],
     supports_credentials=True)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/')
def index():
    return 'Hello with security headers!'

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use proper SSL certs in production
```

### Exercise 2: Test Security Headers

```bash
# Test headers with curl
curl -I http://localhost:3000

# Expected headers:
# Content-Security-Policy: ...
# Strict-Transport-Security: ...
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
```

Use online tools:
- [SecurityHeaders.com](https://securityheaders.com)
- [Mozilla Observatory](https://observatory.mozilla.org)

## Part 2: Container Security with Grype

### What is Grype?

Grype is a vulnerability scanner for container images and filesystems that runs **entirely locally** - perfect for privacy-conscious development.

### Exercise 3: Install Grype

```bash
# macOS
brew install grype

# Linux (recommended method)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
grype version
```

### Exercise 4: Basic Container Scanning

#### Scan a Public Image

```bash
# Scan an older Node.js image (likely has vulnerabilities)
grype node:14-alpine

# Output shows:
# - Vulnerability ID (CVE-2021-xxxxx)
# - Severity (Critical, High, Medium, Low, Negligible)
# - Package name
# - Installed version
# - Fixed version
```

#### Understanding Grype Output

```
NAME                INSTALLED      FIXED-IN     TYPE       VULNERABILITY     SEVERITY
libcrypto1.1        1.1.1k-r0      1.1.1l-r0    apk        CVE-2021-3711     Critical
libssl1.1           1.1.1k-r0      1.1.1l-r0    apk        CVE-2021-3711     Critical
npm                 6.14.13        7.21.0       npm        CVE-2021-37701    High
```

**Severity Levels:**
- **Critical** (9.0-10.0): Remote code execution, data breach
- **High** (7.0-8.9): Privilege escalation, DoS
- **Medium** (4.0-6.9): Information disclosure
- **Low** (0.1-3.9): Minor issues
- **Negligible**: Minimal impact

### Exercise 5: Advanced Grype Usage

#### Output to JSON

```bash
# Get machine-readable output
grype node:14-alpine -o json | jq '.matches[:1]'
```

#### Filter by Severity

```bash
# Fail build if critical vulnerabilities found
grype node:14-alpine --fail-on critical

# Exit code will be non-zero if critical vulnerabilities exist
echo $?
```

#### Exclude False Positives

```bash
# Exclude documentation directories
grype node:14-alpine --exclude /usr/share/doc
```

#### Scan Local Docker Images

```bash
# Build an image
docker build -t myapp:latest .

# Scan it locally (never leaves your machine)
grype myapp:latest
```

#### Scan Filesystems

```bash
# Scan a directory
grype dir:/path/to/project

# Scan current directory
grype dir:.
```

### Exercise 6: Integrate Grype into CI/CD

#### GitHub Actions Example

```yaml
# .github/workflows/security-scan.yml
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan image for vulnerabilities
        run: |
          grype myapp:${{ github.sha }} --fail-on critical

      - name: Generate vulnerability report
        if: always()
        run: |
          grype myapp:${{ github.sha }} -o json > vulnerability-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-report
          path: vulnerability-report.json
```

#### Makefile Integration

```makefile
# Makefile
.PHONY: scan
scan:
	@echo "Scanning container for vulnerabilities..."
	grype $(IMAGE_NAME):$(IMAGE_TAG) --fail-on high

.PHONY: scan-report
scan-report:
	@echo "Generating vulnerability report..."
	grype $(IMAGE_NAME):$(IMAGE_TAG) -o json > grype-report.json
	@echo "Report saved to grype-report.json"

.PHONY: build-and-scan
build-and-scan:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	$(MAKE) scan
```

### Exercise 7: Compare Images

Scan different base images to find the most secure:

```bash
# Scan different Python images
grype python:3.9
grype python:3.9-slim
grype python:3.9-alpine

# Scan different Node images
grype node:16
grype node:16-slim
grype node:16-alpine

# Compare vulnerability counts
```

**Your Task:**
1. Scan 3-4 different base images
2. Count vulnerabilities by severity
3. Choose the most secure option

## Part 3: Combining Headers and Scanning

### Exercise 8: Complete Security Workflow

Create a secure application with both headers and container scanning:

```bash
# 1. Create Dockerfile
cat > Dockerfile <<'EOF'
FROM node:18-alpine

# Install security updates
RUN apk update && apk upgrade

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs

EXPOSE 3000

CMD ["node", "server.js"]
EOF

# 2. Build image
docker build -t secure-app:latest .

# 3. Scan for vulnerabilities
grype secure-app:latest --fail-on critical

# 4. If scan passes, run container
docker run -p 3000:3000 secure-app:latest
```

## Verification Checklist

- [ ] Understand essential HTTP security headers
- [ ] Implemented CSP, HSTS, and other headers
- [ ] Tested headers with online tools
- [ ] Installed Grype
- [ ] Scanned container images for vulnerabilities
- [ ] Interpreted Grype output
- [ ] Integrated Grype into build pipeline
- [ ] Compared different base images for security

## Security Best Practices

### HTTP Headers
1. **Always use HTTPS** - HSTS enforces this
2. **Strict CSP** - Start restrictive, loosen as needed
3. **Test headers** - Use automated tools
4. **Update regularly** - Security standards evolve

### Container Scanning
1. **Scan locally** - No need to send images to external services
2. **Scan frequently** - New CVEs published daily
3. **Choose minimal base images** - Alpine, distroless
4. **Keep images updated** - Rebuild regularly
5. **Fail builds on critical issues** - Don't deploy vulnerable containers

## Discussion Questions

1. Why is CSP effective against XSS attacks?
2. What's the difference between Grype and cloud-based scanners?
3. How does local scanning protect privacy?
4. Why are Alpine images often more secure than full images?
5. What's the trade-off between security and convenience with strict headers?

## Additional Challenges

1. Create a CSP that blocks all inline scripts
2. Set up automated daily container scans
3. Implement EPSS (Exploit Prediction Scoring) filtering
4. Create a vulnerability dashboard
5. Automate base image updates when CVEs are fixed

## Next Steps

In the final lab, you'll learn about GitHub Advanced Security (GHAS), Dependabot, and automated security scanning tools.

## Additional Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Grype Documentation](https://github.com/anchore/grype)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Security Headers Quick Reference](https://securityheaders.com/)
