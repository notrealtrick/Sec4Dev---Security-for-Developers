import * as vscode from 'vscode';
import * as fs from 'fs';

export interface OWASPIssue {
  category: string;
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  owaspReference: string;
}

export class OWASPScanner {
  private owaspPatterns = {
    'A01:2021 - Broken Access Control': {
      patterns: [
        /(?:user|admin|role)\s*[:=]\s*["'](?:admin|root|superuser)["']/gi,
        /(?:isAdmin|isUser|hasRole)\s*\(\s*["'][^"']*["']\s*\)/gi,
        /(?:checkPermission|validateAccess)\s*\(\s*[^)]*\s*\)/gi
      ],
      severity: 'high' as const,
      remediation: 'Implement proper authentication and authorization checks',
      reference: 'A01:2021'
    },
    'A02:2021 - Cryptographic Failures': {
      patterns: [
        /(?:password|secret)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:md5|sha1)\s*\(/gi,
        /(?:crypto|encrypt)\s*\(/gi,
        /(?:base64|btoa|atob)\s*\(/gi
      ],
      severity: 'high' as const,
      remediation: 'Use strong encryption algorithms and secure key management',
      reference: 'A02:2021'
    },
    'A03:2021 - Injection': {
      patterns: [
        /(?:sql|query)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:exec|eval|Function)\s*\(/gi,
        /(?:innerHTML|outerHTML)\s*[:=]/gi,
        /(?:document\.write|document\.writeln)\s*\(/gi
      ],
      severity: 'high' as const,
      remediation: 'Use parameterized queries and input validation',
      reference: 'A03:2021'
    },
    'A04:2021 - Insecure Design': {
      patterns: [
        /(?:debug|test|dev)\s*[:=]\s*true/gi,
        /(?:production|live)\s*[:=]\s*false/gi,
        /(?:localhost|127\.0\.0\.1)/gi
      ],
      severity: 'medium' as const,
      remediation: 'Implement secure design principles and threat modeling',
      reference: 'A04:2021'
    },
    'A05:2021 - Security Misconfiguration': {
      patterns: [
        /(?:cors|origin)\s*[:=]\s*["']\*["']/gi,
        /(?:https|ssl)\s*[:=]\s*false/gi,
        /(?:debug|verbose)\s*[:=]\s*true/gi
      ],
      severity: 'medium' as const,
      remediation: 'Use secure default configurations and regular security updates',
      reference: 'A05:2021'
    },
    'A06:2021 - Vulnerable Components': {
      patterns: [
        /(?:version|ver)\s*[:=]\s*["'](?:1\.0|2\.0|3\.0)["']/gi,
        /(?:deprecated|old|legacy)/gi
      ],
      severity: 'medium' as const,
      remediation: 'Keep dependencies updated and monitor for vulnerabilities',
      reference: 'A06:2021'
    },
    'A07:2021 - Authentication Failures': {
      patterns: [
        /(?:login|auth|password)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:session|token)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:remember|stay)\s*[:=]\s*true/gi
      ],
      severity: 'high' as const,
      remediation: 'Implement strong authentication and session management',
      reference: 'A07:2021'
    },
    'A08:2021 - Software and Data Integrity Failures': {
      patterns: [
        /(?:checksum|hash|signature)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:verify|validate)\s*\(/gi,
        /(?:download|install)\s*\(/gi
      ],
      severity: 'medium' as const,
      remediation: 'Verify software integrity and use secure update mechanisms',
      reference: 'A08:2021'
    },
    'A09:2021 - Security Logging Failures': {
      patterns: [
        /(?:log|logger)\s*[:=]\s*false/gi,
        /(?:console\.log|console\.error)/gi,
        /(?:debug|trace)\s*[:=]\s*false/gi
      ],
      severity: 'low' as const,
      remediation: 'Implement comprehensive logging and monitoring',
      reference: 'A09:2021'
    },
    'A10:2021 - Server-Side Request Forgery': {
      patterns: [
        /(?:fetch|axios|request)\s*\(/gi,
        /(?:url|uri)\s*[:=]\s*["'][^"']*["']/gi,
        /(?:http|https):\/\/[^"'\s]+/gi
      ],
      severity: 'high' as const,
      remediation: 'Validate and sanitize all input URLs',
      reference: 'A10:2021'
    }
  };

  async scan(): Promise<OWASPIssue[]> {
    const issues: OWASPIssue[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,php,java,cs,rb,go}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileIssues = await this.scanFile(file.fsPath);
        issues.push(...fileIssues);
      }

    } catch (error) {
      console.error('Error scanning OWASP issues:', error);
    }

    return issues;
  }

  async scanFile(filePath: string): Promise<OWASPIssue[]> {
    const issues: OWASPIssue[] = [];
    
    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;

        // Check each OWASP category
        for (const [category, config] of Object.entries(this.owaspPatterns)) {
          for (const pattern of config.patterns) {
            const matches = line.matchAll(pattern);
            
            for (const match of matches) {
              issues.push({
                category,
                line: lineNumber,
                code: line.trim(),
                severity: config.severity,
                description: this.getOWASPDescription(category, match[0]),
                remediation: config.remediation,
                owaspReference: config.reference
              });
            }
          }
        }

        // Additional checks for specific vulnerabilities
        const additionalIssues = this.checkAdditionalVulnerabilities(line, lineNumber);
        issues.push(...additionalIssues);
      }

    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }

    return issues;
  }

  private checkAdditionalVulnerabilities(line: string, lineNumber: number): OWASPIssue[] {
    const issues: OWASPIssue[] = [];

    // SQL Injection patterns
    const sqlPatterns = [
      /SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\s*\+/gi,
      /INSERT\s+INTO\s+.*\s+VALUES\s*\([^)]*\+/gi,
      /UPDATE\s+.*\s+SET\s+.*\s+WHERE\s+.*\s*\+/gi,
      /DELETE\s+FROM\s+.*\s+WHERE\s+.*\s*\+/gi
    ];

    for (const pattern of sqlPatterns) {
      if (pattern.test(line)) {
        issues.push({
          category: 'A03:2021 - Injection (SQL)',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Potential SQL injection detected - string concatenation in query',
          remediation: 'Use parameterized queries or prepared statements',
          owaspReference: 'A03:2021'
        });
      }
    }

    // XSS patterns
    const xssPatterns = [
      /innerHTML\s*[:=]\s*[^;]*\+/gi,
      /outerHTML\s*[:=]\s*[^;]*\+/gi,
      /document\.write\s*\([^)]*\+/gi,
      /eval\s*\([^)]*\+/gi
    ];

    for (const pattern of xssPatterns) {
      if (pattern.test(line)) {
        issues.push({
          category: 'A03:2021 - Injection (XSS)',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Potential XSS detected - unvalidated input in DOM manipulation',
          remediation: 'Sanitize all user input and use safe DOM methods',
          owaspReference: 'A03:2021'
        });
      }
    }

    // CSRF patterns
    const csrfPatterns = [
      /(?:csrf|xsrf)\s*[:=]\s*false/gi,
      /(?:token|nonce)\s*[:=]\s*["'][^"']*["']/gi
    ];

    for (const pattern of csrfPatterns) {
      if (pattern.test(line)) {
        issues.push({
          category: 'A01:2021 - Broken Access Control (CSRF)',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Potential CSRF vulnerability - missing or weak token validation',
          remediation: 'Implement proper CSRF tokens and validate them',
          owaspReference: 'A01:2021'
        });
      }
    }

    // Path traversal patterns
    const pathPatterns = [
      /(?:file|path|dir)\s*[:=]\s*[^;]*\+/gi,
      /(?:readFile|writeFile|unlink)\s*\([^)]*\+/gi,
      /(?:\.\.\/|\.\.\\)/gi
    ];

    for (const pattern of pathPatterns) {
      if (pattern.test(line)) {
        issues.push({
          category: 'A01:2021 - Broken Access Control (Path Traversal)',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Potential path traversal vulnerability',
          remediation: 'Validate and sanitize file paths',
          owaspReference: 'A01:2021'
        });
      }
    }

    return issues;
  }

  private getOWASPDescription(category: string, match: string): string {
    switch (category) {
      case 'A01:2021 - Broken Access Control':
        return `Access control issue detected: ${match}`;
      case 'A02:2021 - Cryptographic Failures':
        return `Cryptographic weakness detected: ${match}`;
      case 'A03:2021 - Injection':
        return `Injection vulnerability detected: ${match}`;
      case 'A04:2021 - Insecure Design':
        return `Insecure design pattern detected: ${match}`;
      case 'A05:2021 - Security Misconfiguration':
        return `Security misconfiguration detected: ${match}`;
      case 'A06:2021 - Vulnerable Components':
        return `Vulnerable component detected: ${match}`;
      case 'A07:2021 - Authentication Failures':
        return `Authentication weakness detected: ${match}`;
      case 'A08:2021 - Software and Data Integrity Failures':
        return `Data integrity issue detected: ${match}`;
      case 'A09:2021 - Security Logging Failures':
        return `Logging issue detected: ${match}`;
      case 'A10:2021 - Server-Side Request Forgery':
        return `SSRF vulnerability detected: ${match}`;
      default:
        return `OWASP issue detected: ${match}`;
    }
  }
} 