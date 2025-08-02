"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretScanner = void 0;
const vscode = require("vscode");
const fs = require("fs");
class SecretScanner {
    constructor() {
        this.secretPatterns = {
            api_key: [
                /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["']([^"']{20,})["']/gi,
                /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*`([^`]{20,})`/gi,
                /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*([a-zA-Z0-9]{20,})/gi
            ],
            password: [
                /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']/gi,
                /(?:password|passwd|pwd)\s*[:=]\s*`([^`]{8,})`/gi,
                /(?:password|passwd|pwd)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi
            ],
            token: [
                /(?:token|access_token|bearer_token)\s*[:=]\s*["']([^"']{20,})["']/gi,
                /(?:token|access_token|bearer_token)\s*[:=]\s*`([^`]{20,})`/gi,
                /(?:token|access_token|bearer_token)\s*[:=]\s*([a-zA-Z0-9]{20,})/gi
            ],
            private_key: [
                /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
                /(?:private_key|privatekey|privkey)\s*[:=]\s*["']([^"']{50,})["']/gi
            ],
            database_url: [
                /(?:database_url|db_url|connection_string)\s*[:=]\s*["']([^"']{20,})["']/gi,
                /(?:database_url|db_url|connection_string)\s*[:=]\s*`([^`]{20,})`/gi,
                /(?:mongodb|postgresql|mysql|redis):\/\/[^"'\s]+/gi
            ]
        };
    }
    async scan() {
        const secrets = [];
        try {
            const files = await vscode.workspace.findFiles('**/*.{js,ts,jsx,tsx,py,php,json,yaml,yml,env,config,conf}', '**/node_modules/**');
            for (const file of files) {
                const fileSecrets = await this.scanFile(file.fsPath);
                secrets.push(...fileSecrets);
            }
        }
        catch (error) {
            console.error('Error scanning secrets:', error);
        }
        return secrets;
    }
    async scanFile(filePath) {
        const secrets = [];
        try {
            const content = await fs.promises.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const lineNumber = i + 1;
                // Check each secret type
                for (const [type, patterns] of Object.entries(this.secretPatterns)) {
                    for (const pattern of patterns) {
                        const matches = line.matchAll(pattern);
                        for (const match of matches) {
                            const secretValue = match[1] || match[0];
                            const severity = this.getSecretSeverity(type, secretValue);
                            secrets.push({
                                type: type,
                                line: lineNumber,
                                code: line.trim(),
                                severity,
                                description: this.getSecretDescription(type, secretValue),
                                suggestion: this.getSecretSuggestion(type)
                            });
                        }
                    }
                }
                // Check for hardcoded secrets in comments
                const commentSecrets = this.checkCommentSecrets(line, lineNumber);
                secrets.push(...commentSecrets);
            }
        }
        catch (error) {
            console.error(`Error scanning file ${filePath}:`, error);
        }
        return secrets;
    }
    checkCommentSecrets(line, lineNumber) {
        const secrets = [];
        // Check for secrets in comments
        const commentPatterns = [
            {
                pattern: /\/\/\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
                type: 'password',
                description: 'Hardcoded password in comment'
            },
            {
                pattern: /#\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
                type: 'password',
                description: 'Hardcoded password in comment'
            },
            {
                pattern: /\/\*\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
                type: 'password',
                description: 'Hardcoded password in comment'
            }
        ];
        for (const { pattern, type, description } of commentPatterns) {
            const matches = line.matchAll(pattern);
            for (const match of matches) {
                const secretValue = match[1];
                secrets.push({
                    type,
                    line: lineNumber,
                    code: line.trim(),
                    severity: 'high',
                    description,
                    suggestion: 'Remove hardcoded secrets from comments and use environment variables'
                });
            }
        }
        return secrets;
    }
    getSecretSeverity(type, value) {
        switch (type) {
            case 'private_key':
                return 'high';
            case 'api_key':
            case 'token':
                return value.length > 50 ? 'high' : 'medium';
            case 'password':
                return value.length > 12 ? 'high' : 'medium';
            case 'database_url':
                return 'medium';
            default:
                return 'medium';
        }
    }
    getSecretDescription(type, value) {
        switch (type) {
            case 'api_key':
                return `API key detected: ${value.substring(0, 10)}...`;
            case 'password':
                return `Password detected: ${'*'.repeat(Math.min(value.length, 8))}`;
            case 'token':
                return `Token detected: ${value.substring(0, 10)}...`;
            case 'private_key':
                return 'Private key detected';
            case 'database_url':
                return 'Database connection string detected';
            default:
                return 'Secret detected';
        }
    }
    getSecretSuggestion(type) {
        switch (type) {
            case 'api_key':
                return 'Use environment variables (process.env.API_KEY) or secure configuration management';
            case 'password':
                return 'Use environment variables (process.env.PASSWORD) or secure password management';
            case 'token':
                return 'Use environment variables (process.env.TOKEN) or secure token storage';
            case 'private_key':
                return 'Store private keys in secure key management systems or encrypted files';
            case 'database_url':
                return 'Use environment variables (process.env.DATABASE_URL) for database connections';
            default:
                return 'Move sensitive data to environment variables or secure configuration';
        }
    }
    // Additional checks for specific file types
    async checkEnvFile(filePath) {
        const secrets = [];
        try {
            const content = await fs.promises.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const lineNumber = i + 1;
                // Check for secrets in .env files
                const envPatterns = [
                    {
                        pattern: /^([A-Z_]+)=(.*)$/,
                        type: 'password'
                    }
                ];
                for (const { pattern, type } of envPatterns) {
                    const match = line.match(pattern);
                    if (match) {
                        const [, key, value] = match;
                        if (this.isSecretKey(key) && this.isSecretValue(value)) {
                            secrets.push({
                                type,
                                line: lineNumber,
                                code: line.trim(),
                                severity: 'high',
                                description: `Environment variable ${key} contains secret value`,
                                suggestion: 'Use secure environment variable management or vault services'
                            });
                        }
                    }
                }
            }
        }
        catch (error) {
            console.error(`Error checking env file ${filePath}:`, error);
        }
        return secrets;
    }
    isSecretKey(key) {
        const secretKeywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api', 'auth',
            'credential', 'private', 'database', 'db', 'connection', 'uri', 'url'
        ];
        return secretKeywords.some(keyword => key.toLowerCase().includes(keyword.toLowerCase()));
    }
    isSecretValue(value) {
        // Check if value looks like a secret
        return value.length >= 8 && (/[a-zA-Z0-9!@#$%^&*]{8,}/.test(value) ||
            /^[a-zA-Z0-9+/]{20,}={0,2}$/.test(value) // Base64-like
        );
    }
}
exports.SecretScanner = SecretScanner;
//# sourceMappingURL=secretScanner.js.map