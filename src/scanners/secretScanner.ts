import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface Secret {
  type: 'api_key' | 'password' | 'token' | 'private_key' | 'database_url';
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  suggestion: string;
}

export class SecretScanner {
  private secretPatterns = {
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

  async scan(): Promise<Secret[]> {
    const secrets: Secret[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,php,json,yaml,yml,env,config,conf}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileSecrets = await this.scanFile(file.fsPath);
        secrets.push(...fileSecrets);
      }

    } catch (error) {
      console.error('Error scanning secrets:', error);
    }

    return secrets;
  }

  async scanFile(filePath: string): Promise<Secret[]> {
    const secrets: Secret[] = [];
    
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
              const severity = this.getSecretSeverity(type as any, secretValue);
              
              secrets.push({
                type: type as any,
                line: lineNumber,
                code: line.trim(),
                severity,
                description: this.getSecretDescription(type as any, secretValue),
                suggestion: this.getSecretSuggestion(type as any)
              });
            }
          }
        }

        // Check for hardcoded secrets in comments
        const commentSecrets = this.checkCommentSecrets(line, lineNumber);
        secrets.push(...commentSecrets);
      }

    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }

    return secrets;
  }

  private checkCommentSecrets(line: string, lineNumber: number): Secret[] {
    const secrets: Secret[] = [];
    
    // Check for secrets in comments
    const commentPatterns = [
      {
        pattern: /\/\/\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
        type: 'password' as const,
        description: 'Hardcoded password in comment'
      },
      {
        pattern: /#\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
        type: 'password' as const,
        description: 'Hardcoded password in comment'
      },
      {
        pattern: /\/\*\s*(?:password|api_key|token)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*]{8,})/gi,
        type: 'password' as const,
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

  private getSecretSeverity(type: Secret['type'], value: string): 'high' | 'medium' | 'low' {
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

  private getSecretDescription(type: Secret['type'], value: string): string {
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

  private getSecretSuggestion(type: Secret['type']): string {
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
  private async checkEnvFile(filePath: string): Promise<Secret[]> {
    const secrets: Secret[] = [];
    
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
            type: 'password' as const
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

    } catch (error) {
      console.error(`Error checking env file ${filePath}:`, error);
    }

    return secrets;
  }

  private isSecretKey(key: string): boolean {
    const secretKeywords = [
      'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api', 'auth',
      'credential', 'private', 'database', 'db', 'connection', 'uri', 'url'
    ];
    
    return secretKeywords.some(keyword => 
      key.toLowerCase().includes(keyword.toLowerCase())
    );
  }

  private isSecretValue(value: string): boolean {
    // Check if value looks like a secret
    return value.length >= 8 && (
      /[a-zA-Z0-9!@#$%^&*]{8,}/.test(value) ||
      /^[a-zA-Z0-9+/]{20,}={0,2}$/.test(value) // Base64-like
    );
  }
} 