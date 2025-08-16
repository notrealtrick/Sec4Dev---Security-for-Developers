import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface DockerfileIssue {
  type: 'security' | 'best_practice' | 'vulnerability' | 'configuration';
  line: number;
  code: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  cve?: string;
}

export interface IaCIssue {
  type: 'security' | 'compliance' | 'configuration' | 'vulnerability';
  line: number;
  code: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  resource?: string;
}

export class DockerfileScanner {
  private dockerfilePatterns = [
    // Security issues
    {
      pattern: /^FROM\s+.*:latest/i,
      type: 'security',
      severity: 'high' as const,
      description: 'Using latest tag can lead to unexpected behavior and security issues',
      remediation: 'Use specific version tags instead of latest'
    },
    {
      pattern: /^USER\s+root/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Running container as root is a major security risk',
      remediation: 'Create a non-root user and use USER directive'
    },
    {
      pattern: /^RUN\s+.*\bcurl\b.*\|\s*bash/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Piping curl to bash is dangerous and can execute malicious code',
      remediation: 'Download, verify checksums, then install packages'
    },
    {
      pattern: /^COPY\s+.*\/etc\/passwd/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Copying /etc/passwd can expose sensitive user information',
      remediation: 'Avoid copying system files unless absolutely necessary'
    },
    {
      pattern: /^EXPOSE\s+.*/i,
      type: 'configuration',
      severity: 'medium' as const,
      description: 'Exposing ports without proper documentation',
      remediation: 'Document why ports are exposed and consider security implications'
    },
    {
      pattern: /^ENV\s+.*PASSWORD.*=/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Setting passwords in environment variables is insecure',
      remediation: 'Use secrets management or build-time arguments'
    },
    {
      pattern: /^RUN\s+.*\bwget\b.*\|\s*bash/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Piping wget to bash is dangerous',
      remediation: 'Download, verify, then install packages'
    },
    {
      pattern: /^ADD\s+.*http/i,
      type: 'security',
      severity: 'high' as const,
      description: 'ADD with URLs can be unpredictable and insecure',
      remediation: 'Use COPY for local files, download separately for URLs'
    },
    {
      pattern: /^RUN\s+.*\bapt-get\b.*\|\s*bash/i,
      type: 'security',
      severity: 'high' as const,
      description: 'Piping apt-get to bash can execute malicious scripts',
      remediation: 'Use apt-get update && apt-get install directly'
    },
    {
      pattern: /^RUN\s+.*\byum\b.*\|\s*bash/i,
      type: 'security',
      severity: 'high' as const,
      description: 'Piping yum to bash can execute malicious scripts',
      remediation: 'Use yum install directly'
    }
  ];

  async scanFile(filePath: string): Promise<DockerfileIssue[]> {
    const issues: DockerfileIssue[] = [];
    
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        const lineNumber = index + 1;
        const trimmedLine = line.trim();

        // Skip comments and empty lines
        if (trimmedLine.startsWith('#') || trimmedLine === '') {
          return;
        }

        // Check each pattern
        this.dockerfilePatterns.forEach(pattern => {
          if (pattern.pattern.test(trimmedLine)) {
            issues.push({
              type: pattern.type,
              line: lineNumber,
              code: trimmedLine,
              severity: pattern.severity,
              description: pattern.description,
              remediation: pattern.remediation
            });
          }
        });

        // Additional checks
        this.checkAdditionalSecurityIssues(trimmedLine, lineNumber, issues);
      });

    } catch (error) {
      console.error(`Error scanning Dockerfile ${filePath}:`, error);
    }

    return issues;
  }

  private checkAdditionalSecurityIssues(line: string, lineNumber: number, issues: DockerfileIssue[]) {
    // Check for hardcoded secrets
    if (line.match(/password\s*=\s*['"][^'"]+['"]/i)) {
      issues.push({
        type: 'security',
        line: lineNumber,
        code: line,
        severity: 'critical',
        description: 'Hardcoded password detected',
        remediation: 'Use build arguments or secrets management'
      });
    }

    // Check for unnecessary packages
    if (line.match(/RUN\s+.*\b(ssh|telnet|ftp)\b/i)) {
      issues.push({
        type: 'security',
        line: lineNumber,
        code: line,
        severity: 'medium',
        description: 'Installing unnecessary network tools',
        remediation: 'Remove unnecessary packages to reduce attack surface'
      });
    }

    // Check for world-writable files
    if (line.match(/RUN\s+.*chmod\s+777/i)) {
      issues.push({
        type: 'security',
        line: lineNumber,
        code: line,
        severity: 'high',
        description: 'Setting world-writable permissions',
        remediation: 'Use more restrictive permissions (755 or 644)'
      });
    }
  }

  async scanWorkspace(): Promise<DockerfileIssue[]> {
    const issues: DockerfileIssue[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/Dockerfile*',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileIssues = await this.scanFile(file.fsPath);
        issues.push(...fileIssues);
      }

    } catch (error) {
      console.error('Error scanning workspace for Dockerfiles:', error);
    }

    return issues;
  }
}

export class IaCScanner {
  private terraformPatterns = [
    {
      pattern: /resource\s+"aws_s3_bucket".*public_access_block\s*{/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'S3 bucket without proper access controls',
      remediation: 'Add public_access_block configuration'
    },
    {
      pattern: /resource\s+"aws_security_group".*ingress\s*{.*cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Security group allowing access from anywhere',
      remediation: 'Restrict CIDR blocks to specific IP ranges'
    },
    {
      pattern: /resource\s+"aws_iam_user".*force_detach_policies\s*=\s*false/i,
      type: 'security',
      severity: 'medium' as const,
      description: 'IAM user without force detach policies',
      remediation: 'Set force_detach_policies = true'
    }
  ];

  private kubernetesPatterns = [
    {
      pattern: /securityContext:\s*{.*runAsNonRoot:\s*false/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Container running as root',
      remediation: 'Set runAsNonRoot: true and runAsUser'
    },
    {
      pattern: /securityContext:\s*{.*privileged:\s*true/i,
      type: 'security',
      severity: 'critical' as const,
      description: 'Container running in privileged mode',
      remediation: 'Avoid privileged containers unless absolutely necessary'
    },
    {
      pattern: /imagePullPolicy:\s*Always/i,
      type: 'configuration',
      severity: 'medium' as const,
      description: 'Always pulling images can lead to unexpected behavior',
      remediation: 'Use IfNotPresent or specific image tags'
    }
  ];

  async scanFile(filePath: string): Promise<IaCIssue[]> {
    const issues: IaCIssue[] = [];
    
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      const fileExtension = path.extname(filePath).toLowerCase();

      lines.forEach((line, index) => {
        const lineNumber = index + 1;
        const trimmedLine = line.trim();

        // Skip comments and empty lines
        if (trimmedLine.startsWith('#') || trimmedLine.startsWith('//') || trimmedLine === '') {
          return;
        }

        // Terraform files
        if (fileExtension === '.tf' || fileExtension === '.tfvars') {
          this.checkTerraformPatterns(trimmedLine, lineNumber, issues);
        }

        // Kubernetes files
        if (fileExtension === '.yaml' || fileExtension === '.yml') {
          this.checkKubernetesPatterns(trimmedLine, lineNumber, issues);
        }

        // Additional checks
        this.checkAdditionalIaCIssues(trimmedLine, lineNumber, issues, fileExtension);
      });

    } catch (error) {
      console.error(`Error scanning IaC file ${filePath}:`, error);
    }

    return issues;
  }

  private checkTerraformPatterns(line: string, lineNumber: number, issues: IaCIssue[]) {
    this.terraformPatterns.forEach(pattern => {
      if (pattern.pattern.test(line)) {
        issues.push({
          type: pattern.type,
          line: lineNumber,
          code: line,
          severity: pattern.severity,
          description: pattern.description,
          remediation: pattern.remediation
        });
      }
    });
  }

  private checkKubernetesPatterns(line: string, lineNumber: number, issues: IaCIssue[]) {
    this.kubernetesPatterns.forEach(pattern => {
      if (pattern.pattern.test(line)) {
        issues.push({
          type: pattern.type,
          line: lineNumber,
          code: line,
          severity: pattern.severity,
          description: pattern.description,
          remediation: pattern.remediation
        });
      }
    });
  }

  private checkAdditionalIaCIssues(line: string, lineNumber: number, issues: IaCIssue[], fileExtension: string) {
    // Check for hardcoded secrets
    if (line.match(/password\s*=\s*['"][^'"]+['"]/i) || line.match(/secret\s*=\s*['"][^'"]+['"]/i)) {
      issues.push({
        type: 'security',
        line: lineNumber,
        code: line,
        severity: 'critical',
        description: 'Hardcoded secret detected',
        remediation: 'Use variables, environment variables, or secrets management'
      });
    }

    // Check for overly permissive policies
    if (line.match(/"Effect":\s*"Allow".*"Action":\s*"\*"/i)) {
      issues.push({
        type: 'security',
        line: lineNumber,
        code: line,
        severity: 'critical',
        description: 'Overly permissive IAM policy',
        remediation: 'Use principle of least privilege with specific actions'
      });
    }
  }

  async scanWorkspace(): Promise<IaCIssue[]> {
    const issues: IaCIssue[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{tf,tfvars,yaml,yml}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileIssues = await this.scanFile(file.fsPath);
        issues.push(...fileIssues);
      }

    } catch (error) {
      console.error('Error scanning workspace for IaC files:', error);
    }

    return issues;
  }
} 