"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HoverProvider = void 0;
const vscode = require("vscode");
class HoverProvider {
    provideHover(document, position, token) {
        const line = document.lineAt(position.line);
        const lineText = line.text;
        // Check for security issues at the current position
        const securityInfo = this.getSecurityInfo(lineText, position.character);
        if (securityInfo) {
            const contents = new vscode.MarkdownString();
            contents.appendMarkdown(`**🔒 Security Issue: ${securityInfo.title}**\n\n`);
            contents.appendMarkdown(`${securityInfo.description}\n\n`);
            contents.appendMarkdown(`**Risk Level:** ${securityInfo.riskLevel}\n\n`);
            contents.appendMarkdown(`**Recommendation:** ${securityInfo.recommendation}\n\n`);
            contents.appendMarkdown(`**Example Fix:**\n\`\`\`\n${securityInfo.example}\n\`\`\``);
            return new vscode.Hover(contents);
        }
        return null;
    }
    getSecurityInfo(lineText, character) {
        // Check for eval usage
        if (this.isInRange(lineText, character, /eval\s*\(/)) {
            return {
                title: 'Eval() Usage Detected',
                description: 'Using eval() can execute arbitrary code and is a major security risk.',
                riskLevel: 'HIGH',
                recommendation: 'Replace eval() with safer alternatives like JSON.parse() for JSON data.',
                example: '// Instead of: eval(userInput)\n// Use: JSON.parse(userInput) // for JSON data\n// Or: Function("return " + userInput)() // for expressions'
            };
        }
        // Check for hardcoded secrets
        if (this.isInRange(lineText, character, /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["'][^"']{20,}["']/)) {
            return {
                title: 'Hardcoded API Key Detected',
                description: 'API keys should not be hardcoded in source code.',
                riskLevel: 'HIGH',
                recommendation: 'Move API keys to environment variables or secure configuration management.',
                example: '// Instead of: api_key = "sk-1234567890abcdef"\n// Use: api_key = process.env.API_KEY'
            };
        }
        if (this.isInRange(lineText, character, /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/)) {
            return {
                title: 'Hardcoded Password Detected',
                description: 'Passwords should not be hardcoded in source code.',
                riskLevel: 'HIGH',
                recommendation: 'Use environment variables or secure password management.',
                example: '// Instead of: password = "mypassword123"\n// Use: password = process.env.PASSWORD'
            };
        }
        // Check for SQL injection
        if (this.isInRange(lineText, character, /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\s+WHERE\s+.*\s*\+/)) {
            return {
                title: 'Potential SQL Injection',
                description: 'String concatenation in SQL queries can lead to SQL injection attacks.',
                riskLevel: 'HIGH',
                recommendation: 'Use parameterized queries or prepared statements.',
                example: '// Instead of: "SELECT * FROM users WHERE id = " + userId\n// Use: "SELECT * FROM users WHERE id = ?" with parameters'
            };
        }
        // Check for XSS
        if (this.isInRange(lineText, character, /(?:innerHTML|outerHTML)\s*[:=]/)) {
            return {
                title: 'Potential XSS Vulnerability',
                description: 'Setting innerHTML/outerHTML with user input can lead to XSS attacks.',
                riskLevel: 'HIGH',
                recommendation: 'Sanitize user input or use textContent instead.',
                example: '// Instead of: element.innerHTML = userInput\n// Use: element.textContent = userInput\n// Or: element.innerHTML = DOMPurify.sanitize(userInput)'
            };
        }
        // Check for base64 encoding
        if (this.isInRange(lineText, character, /(?:base64|btoa|atob)\s*\(/)) {
            return {
                title: 'Base64 Encoding/Decoding',
                description: 'Base64 encoding is not encryption and should not be used to hide sensitive data.',
                riskLevel: 'MEDIUM',
                recommendation: 'Use proper encryption for sensitive data.',
                example: '// Instead of: btoa(sensitiveData)\n// Use: crypto.createHash("sha256").update(sensitiveData).digest("hex")'
            };
        }
        // Check for localhost references
        if (this.isInRange(lineText, character, /(?:localhost|127\.0\.0\.1)/)) {
            return {
                title: 'Localhost Reference',
                description: 'Hardcoded localhost references may indicate development code in production.',
                riskLevel: 'MEDIUM',
                recommendation: 'Use environment variables for configuration.',
                example: '// Instead of: "http://localhost:3000"\n// Use: process.env.API_URL || "http://localhost:3000"'
            };
        }
        // Check for HTTP URLs
        if (this.isInRange(lineText, character, /http:\/\//)) {
            return {
                title: 'Insecure HTTP URL',
                description: 'HTTP URLs transmit data in plain text and are vulnerable to interception.',
                riskLevel: 'MEDIUM',
                recommendation: 'Use HTTPS for all external communications.',
                example: '// Instead of: "http://api.example.com"\n// Use: "https://api.example.com"'
            };
        }
        // Check for console.log in production
        if (this.isInRange(lineText, character, /console\.(log|error|warn)/)) {
            return {
                title: 'Console Logging',
                description: 'Console logs may expose sensitive information and should be removed in production.',
                riskLevel: 'LOW',
                recommendation: 'Use proper logging framework and remove console logs from production.',
                example: '// Instead of: console.log(sensitiveData)\n// Use: logger.info("User action", { userId: user.id })'
            };
        }
        return null;
    }
    isInRange(lineText, character, pattern) {
        const match = lineText.match(pattern);
        if (!match)
            return false;
        const startIndex = lineText.indexOf(match[0]);
        const endIndex = startIndex + match[0].length;
        return character >= startIndex && character <= endIndex;
    }
}
exports.HoverProvider = HoverProvider;
//# sourceMappingURL=hoverProvider.js.map