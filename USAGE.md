# Sec4Dev Advanced Usage Guide

This guide covers the advanced features of Sec4Dev v2.0.0, including Dockerfile scanning, IaC analysis, taint analysis, API security testing, AI risk prioritization, and security training.

## Table of Contents

1. [Dockerfile and IaC Security Scanning](#dockerfile-and-iac-security-scanning)
2. [AI Risk Prioritization](#ai-risk-prioritization)
3. [Data Flow Analysis (Taint Analysis)](#data-flow-analysis-taint-analysis)
4. [API Security Testing](#api-security-testing)
5. [Security Training Module](#security-training-module)
6. [Advanced Configuration](#advanced-configuration)
7. [Best Practices](#best-practices)

## Dockerfile and IaC Security Scanning

### Dockerfile Security Analysis

Sec4Dev can scan Dockerfiles for common security vulnerabilities and best practices.

#### Supported Vulnerabilities:
- **Using latest tags** - Can lead to unexpected behavior
- **Running as root** - Major security risk
- **Piping curl/wget to bash** - Dangerous code execution
- **Hardcoded passwords** - Insecure credential storage
- **Copying system files** - Potential information disclosure
- **World-writable permissions** - Excessive access rights

#### Usage:
```bash
# Scan current workspace for Dockerfile issues
Sec4Dev: Dockerfile Security Scan
```

#### Example Vulnerable Dockerfile:
```dockerfile
FROM node:latest
USER root
RUN curl http://example.com/script.sh | bash
ENV PASSWORD=secret123
COPY /etc/passwd /tmp/
RUN chmod 777 /app
```

#### Secure Dockerfile:
```dockerfile
FROM node:18-alpine
RUN adduser -D appuser
USER appuser
RUN wget https://example.com/script.sh && \
    sha256sum script.sh && \
    bash script.sh
ENV PASSWORD=""
COPY --chown=appuser:appuser . /app
RUN chmod 755 /app
```

### Infrastructure as Code (IaC) Security Analysis

Sec4Dev supports scanning Terraform, Kubernetes, and other IaC files.

#### Supported Frameworks:
- **Terraform** - AWS, Azure, GCP configurations
- **Kubernetes** - YAML manifests
- **CloudFormation** - AWS CloudFormation templates

#### Common IaC Vulnerabilities:
- **Public S3 buckets** - Missing access controls
- **Open security groups** - Allowing all traffic (0.0.0.0/0)
- **Overly permissive IAM policies** - Using wildcards (*)
- **Privileged containers** - Running as root
- **Hardcoded secrets** - Credentials in code

#### Usage:
```bash
# Scan current workspace for IaC issues
Sec4Dev: Infrastructure as Code Security Scan
```

#### Example Vulnerable Terraform:
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # Missing public_access_block
}

resource "aws_security_group" "web" {
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow all traffic
  }
}
```

#### Secure Terraform:
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  public_access_block {
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Specific CIDR
  }
}
```

## AI Risk Prioritization

The AI risk prioritization feature analyzes security issues based on context, impact, and likelihood to provide intelligent recommendations.

### Risk Assessment Factors:

#### Context Factors:
- **Environment** (production vs development)
- **Public exposure** (internet-facing vs internal)
- **Data sensitivity** (PII, financial data, etc.)
- **User input handling** (direct user input vs internal data)
- **Authentication requirements** (authenticated vs anonymous)

#### Impact Assessment:
- **Severe** - Data breach, system compromise
- **Moderate** - Service disruption, compliance violation
- **Minor** - Limited business impact

#### Likelihood Assessment:
- **Very likely** - Known vulnerabilities, active exploitation
- **Likely** - Public exposure, weak controls
- **Unlikely** - Complex attacks, strong controls
- **Very unlikely** - Theoretical attacks

### Usage:
```bash
# Run AI risk prioritization on all detected issues
Sec4Dev: AI Risk Prioritization
```

### Output Example:
```
🎯 Risk Prioritization Results

Priority Score: 95.2
Issue: SQL Injection - Line 45
Risk Level: CRITICAL
Impact: Severe
Likelihood: Very likely
Confidence: 85%
Recommended Action: Fix immediately - Stop deployment if in production
Time to Fix: Immediate
Effort: Medium
```

## Data Flow Analysis (Taint Analysis)

Taint analysis tracks data flow from untrusted sources to sensitive sinks, identifying potential security vulnerabilities.

### Source Types:
- **User input** - HTTP requests, form data
- **Network** - External API calls, file downloads
- **File system** - File reads, configuration files
- **Environment** - Environment variables, command line args
- **Database** - Database queries, stored procedures
- **Third-party** - External libraries, APIs

### Sink Types:
- **SQL queries** - Database operations
- **Code execution** - eval(), Function(), exec()
- **File operations** - File writes, system calls
- **XSS output** - innerHTML, document.write()
- **Authentication** - Password verification, session management

### Usage:
```bash
# Run taint analysis on current workspace
Sec4Dev: Data Flow Analysis (Taint Analysis)
```

### Example Vulnerable Flow:
```javascript
// Source: User input
const userInput = req.body.query;

// Sink: SQL query (vulnerable)
const query = `SELECT * FROM products WHERE name LIKE '%${userInput}%'`;
db.query(query, (err, results) => {
  res.json(results);
});
```

### Secure Flow:
```javascript
// Source: User input
const userInput = req.body.query;

// Input validation
if (!userInput || userInput.length > 100) {
  return res.status(400).json({ error: 'Invalid query' });
}

// Sink: Parameterized query (secure)
const query = 'SELECT * FROM products WHERE name LIKE ?';
db.query(query, [`%${userInput}%`], (err, results) => {
  res.json(results);
});
```

## API Security Testing

The API security testing module analyzes API endpoints for common security vulnerabilities and generates test cases.

### Supported Frameworks:
- **Express.js** - Node.js web framework
- **FastAPI** - Python web framework
- **Flask** - Python micro-framework
- **Django** - Python web framework

### Security Checks:
- **Authentication** - Missing or weak authentication
- **Authorization** - Missing role-based access control
- **Input validation** - Missing input sanitization
- **Output sanitization** - Missing output encoding
- **Rate limiting** - Missing rate limiting
- **SQL injection** - Direct query construction
- **XSS** - Unsafe HTML output
- **Information disclosure** - Hardcoded secrets

### Usage:
```bash
# Run API security analysis
Sec4Dev: API Security Testing
```

### Example Vulnerable API:
```javascript
// Missing authentication
app.get('/api/users', (req, res) => {
  const users = db.query('SELECT * FROM users');
  res.json(users);
});

// SQL injection vulnerable
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ success: true });
    }
  });
});
```

### Secure API:
```javascript
// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Authorization middleware
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Secure endpoints
app.get('/api/users', authenticateToken, authorizeRole('admin'), (req, res) => {
  const users = db.query('SELECT id, name, email FROM users');
  res.json(users);
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  
  // Parameterized query
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password_hash, (err, isMatch) => {
        if (isMatch) {
          const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
          res.json({ token });
        } else {
          res.status(401).json({ error: 'Invalid credentials' });
        }
      });
    }
  });
});
```

## Security Training Module

The security training module provides interactive lessons on security best practices.

### Available Lessons:

#### Beginner Level:
1. **SQL Injection Fundamentals**
   - Understanding SQL injection attacks
   - Prevention techniques
   - Code examples and explanations

2. **Cross-Site Scripting (XSS) Prevention**
   - Types of XSS attacks
   - Output encoding techniques
   - Content Security Policy

#### Intermediate Level:
3. **Secure Authentication Implementation**
   - Password hashing with bcrypt
   - Multi-factor authentication
   - Session management
   - Rate limiting

#### Advanced Level:
4. **Advanced Security Patterns**
   - Secure coding practices
   - Threat modeling
   - Security architecture

### Features:
- **Interactive lessons** with code examples
- **Quiz-based learning** with immediate feedback
- **Progress tracking** and certificates
- **Best practices** education
- **Real-world examples** and case studies

### Usage:
```bash
# Open security training module
Sec4Dev: Security Training Module
```

### Example Lesson Structure:
```
🎓 SQL Injection Fundamentals

📚 Content:
- What is SQL injection?
- Common attack vectors
- Prevention techniques

💻 Code Examples:
- Vulnerable code
- Secure alternatives
- Detailed explanations

❓ Quiz:
- Multiple choice questions
- Immediate feedback
- Explanations for each answer

📖 Resources:
- OWASP documentation
- Cheat sheets
- Additional reading
```

## Advanced Configuration

### VS Code Settings

Configure Sec4Dev behavior through VS Code settings:

```json
{
  "sec4dev.enableRealTimeScanning": true,
  "sec4dev.showWarnings": true,
  "sec4dev.enableDependencyScanning": true,
  "sec4dev.enableSecretScanning": true,
  "sec4dev.enableOWASPScanning": true,
  "sec4dev.enableAIAnalysis": true,
  "sec4dev.enableTerminalScanning": true,
  "sec4dev.autoScanOnSave": false,
  "sec4dev.autoScanOnCommit": true,
  "sec4dev.securityScoreThreshold": 70
}
```

### Custom Patterns

You can extend Sec4Dev with custom security patterns:

```javascript
// Custom vulnerability patterns
const customPatterns = [
  {
    pattern: /customVulnerableFunction\s*\(/gi,
    type: 'custom_vulnerability',
    severity: 'high',
    description: 'Custom vulnerable function detected',
    remediation: 'Use secure alternative function'
  }
];
```

## Best Practices

### 1. Regular Scanning
- Run comprehensive scans before each release
- Integrate scanning into CI/CD pipelines
- Schedule regular security assessments

### 2. Risk Management
- Prioritize critical vulnerabilities first
- Consider business impact and technical risk
- Maintain a security backlog

### 3. Secure Development
- Follow secure coding practices
- Use security training modules
- Implement security code reviews

### 4. Continuous Improvement
- Track security metrics over time
- Learn from security incidents
- Stay updated with security best practices

### 5. Team Education
- Regular security training sessions
- Share security knowledge
- Foster security culture

## Troubleshooting

### Common Issues:

1. **False Positives**
   - Review and adjust pattern sensitivity
   - Add custom exclusions
   - Validate findings manually

2. **Performance Issues**
   - Limit scan scope for large codebases
   - Use incremental scanning
   - Optimize scan frequency

3. **Integration Problems**
   - Check VS Code extension compatibility
   - Verify file permissions
   - Review error logs

### Getting Help:

- Check the README for basic usage
- Review example files for patterns
- Consult security documentation
- Report issues on GitHub

## Conclusion

Sec4Dev v2.0.0 provides comprehensive security analysis capabilities for modern development workflows. By combining static analysis, AI-powered risk assessment, and interactive training, it helps teams build more secure applications.

Remember that security is an ongoing process. Regular scanning, continuous learning, and proactive security practices are essential for maintaining secure codebases.