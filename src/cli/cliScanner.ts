import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface CLIScanResult {
  filesScanned: number;
  issuesFound: number;
  securityScore: number;
  summary: {
    evalCount: number;
    secretsCount: number;
    vulnerabilitiesCount: number;
    owaspIssuesCount: number;
  };
  details: {
    file: string;
    issues: string[];
    score: number;
  }[];
}

export class CLIScanner {
  async scan(): Promise<CLIScanResult> {
    const result: CLIScanResult = {
      filesScanned: 0,
      issuesFound: 0,
      securityScore: 100,
      summary: {
        evalCount: 0,
        secretsCount: 0,
        vulnerabilitiesCount: 0,
        owaspIssuesCount: 0
      },
      details: []
    };

    try {
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceRoot) {
        return result;
      }

      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,php,json,yaml,yml}',
        '**/node_modules/**'
      );

      result.filesScanned = files.length;

      for (const file of files) {
        const fileResult = await this.scanFile(file.fsPath);
        result.details.push(fileResult);
        
        // Update summary
        result.summary.evalCount += fileResult.evalCount;
        result.summary.secretsCount += fileResult.secretsCount;
        result.summary.vulnerabilitiesCount += fileResult.vulnerabilitiesCount;
        result.summary.owaspIssuesCount += fileResult.owaspIssuesCount;
        
        result.issuesFound += fileResult.issues.length;
      }

      // Calculate overall security score
      result.securityScore = this.calculateOverallScore(result);

    } catch (error) {
      console.error('Error in CLI scan:', error);
    }

    return result;
  }

  private async scanFile(filePath: string): Promise<{
    file: string;
    issues: string[];
    score: number;
    evalCount: number;
    secretsCount: number;
    vulnerabilitiesCount: number;
    owaspIssuesCount: number;
  }> {
    const result = {
      file: path.basename(filePath),
      issues: [] as string[],
      score: 100,
      evalCount: 0,
      secretsCount: 0,
      vulnerabilitiesCount: 0,
      owaspIssuesCount: 0
    };

    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;

        // Check for eval usage
        if (line.includes('eval(')) {
          result.evalCount++;
          result.issues.push(`Line ${lineNumber}: eval() usage detected`);
          result.score -= 20;
        }

        // Check for secrets
        const secretPatterns = [
          { pattern: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["'][^"']{20,}["']/gi, type: 'API Key' },
          { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi, type: 'Password' },
          { pattern: /(?:token|access_token|bearer_token)\s*[:=]\s*["'][^"']{20,}["']/gi, type: 'Token' }
        ];

        for (const { pattern, type } of secretPatterns) {
          if (pattern.test(line)) {
            result.secretsCount++;
            result.issues.push(`Line ${lineNumber}: Hardcoded ${type} detected`);
            result.score -= 15;
          }
        }

        // Check for vulnerabilities
        const vulnerabilityPatterns = [
          { pattern: /Function\s*\(\s*["'][^"']*["']/gi, type: 'Function constructor' },
          { pattern: /setTimeout\s*\(\s*["'][^"']*["']/gi, type: 'setTimeout with string' },
          { pattern: /setInterval\s*\(\s*["'][^"']*["']/gi, type: 'setInterval with string' },
          { pattern: /exec\s*\(/gi, type: 'Process execution' },
          { pattern: /spawn\s*\(/gi, type: 'Process spawning' }
        ];

        for (const { pattern, type } of vulnerabilityPatterns) {
          if (pattern.test(line)) {
            result.vulnerabilitiesCount++;
            result.issues.push(`Line ${lineNumber}: ${type} detected`);
            result.score -= 10;
          }
        }

        // Check for OWASP issues
        const owaspPatterns = [
          { pattern: /(?:sql|query)\s*[:=]\s*["'][^"']*["']/gi, type: 'SQL injection risk' },
          { pattern: /(?:innerHTML|outerHTML)\s*[:=]/gi, type: 'XSS risk' },
          { pattern: /(?:document\.write|document\.writeln)\s*\(/gi, type: 'XSS risk' },
          { pattern: /(?:localhost|127\.0\.0\.1)/gi, type: 'Localhost reference' },
          { pattern: /http:\/\//gi, type: 'Insecure HTTP URL' }
        ];

        for (const { pattern, type } of owaspPatterns) {
          if (pattern.test(line)) {
            result.owaspIssuesCount++;
            result.issues.push(`Line ${lineNumber}: ${type} detected`);
            result.score -= 8;
          }
        }
      }

      result.score = Math.max(0, result.score);

    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }

    return result;
  }

  private calculateOverallScore(result: CLIScanResult): number {
    let score = 100;

    // Deduct points based on issues found
    score -= result.summary.evalCount * 20;
    score -= result.summary.secretsCount * 15;
    score -= result.summary.vulnerabilitiesCount * 10;
    score -= result.summary.owaspIssuesCount * 8;

    return Math.max(0, Math.min(100, score));
  }

  // Generate CLI output
  generateCLIOutput(result: CLIScanResult): string {
    let output = '';

    output += '🔒 Sec4Dev CLI Security Scan Results\n';
    output += '=====================================\n\n';

    output += `📊 Summary:\n`;
    output += `   Files Scanned: ${result.filesScanned}\n`;
    output += `   Issues Found: ${result.issuesFound}\n`;
    output += `   Security Score: ${result.securityScore}/100\n\n`;

    output += `📈 Breakdown:\n`;
    output += `   Eval Usage: ${result.summary.evalCount}\n`;
    output += `   Secrets: ${result.summary.secretsCount}\n`;
    output += `   Vulnerabilities: ${result.summary.vulnerabilitiesCount}\n`;
    output += `   OWASP Issues: ${result.summary.owaspIssuesCount}\n\n`;

    if (result.details.length > 0) {
      output += `📁 File Details:\n`;
      for (const detail of result.details) {
        if (detail.issues.length > 0) {
          output += `   ${detail.file} (Score: ${detail.score}/100)\n`;
          for (const issue of detail.issues.slice(0, 3)) { // Show first 3 issues
            output += `     - ${issue}\n`;
          }
          if (detail.issues.length > 3) {
            output += `     ... and ${detail.issues.length - 3} more issues\n`;
          }
          output += '\n';
        }
      }
    }

    // Add recommendations
    output += `💡 Recommendations:\n`;
    if (result.summary.evalCount > 0) {
      output += `   - Replace ${result.summary.evalCount} eval() usage with safer alternatives\n`;
    }
    if (result.summary.secretsCount > 0) {
      output += `   - Move ${result.summary.secretsCount} hardcoded secrets to environment variables\n`;
    }
    if (result.summary.vulnerabilitiesCount > 0) {
      output += `   - Review ${result.summary.vulnerabilitiesCount} potential vulnerabilities\n`;
    }
    if (result.summary.owaspIssuesCount > 0) {
      output += `   - Address ${result.summary.owaspIssuesCount} OWASP Top 10 issues\n`;
    }

    if (result.securityScore < 60) {
      output += `   - Critical: Immediate security review required\n`;
    } else if (result.securityScore < 80) {
      output += `   - Warning: Security improvements needed\n`;
    } else {
      output += `   - Good: Security practices are being followed\n`;
    }

    return output;
  }
} 