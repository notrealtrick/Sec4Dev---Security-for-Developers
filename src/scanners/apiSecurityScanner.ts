import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface APIEndpoint {
  method: string;
  path: string;
  line: number;
  parameters: APIParameter[];
  authentication: boolean;
  authorization: boolean;
  rateLimit: boolean;
  inputValidation: boolean;
  outputSanitization: boolean;
}

export interface APIParameter {
  name: string;
  type: string;
  required: boolean;
  validation: string[];
  sanitization: string[];
}

export interface APIVulnerability {
  type: 'authentication' | 'authorization' | 'input_validation' | 'output_sanitization' | 'rate_limiting' | 'sql_injection' | 'xss' | 'csrf' | 'injection' | 'information_disclosure';
  endpoint: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  cwe?: string;
  testCase?: APITestCase;
}

export interface APITestCase {
  name: string;
  method: string;
  url: string;
  headers: { [key: string]: string };
  body?: any;
  expectedResponse: number;
  description: string;
  payload: string;
}

export interface APISecurityTest {
  name: string;
  description: string;
  testCases: APITestCase[];
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export class APISecurityScanner {
  private endpoints: APIEndpoint[] = [];
  private vulnerabilities: APIVulnerability[] = [];
  private securityTests: APISecurityTest[] = [];

  // API framework patterns
  private frameworkPatterns = [
    {
      name: 'Express.js',
      patterns: [
        /app\.(get|post|put|delete|patch)\(/gi,
        /router\.(get|post|put|delete|patch)\(/gi
      ]
    },
    {
      name: 'FastAPI',
      patterns: [
        /@app\.(get|post|put|delete|patch)\(/gi,
        /@router\.(get|post|put|delete|patch)\(/gi
      ]
    },
    {
      name: 'Flask',
      patterns: [
        /@app\.route\(/gi,
        /@blueprint\.route\(/gi
      ]
    },
    {
      name: 'Django',
      patterns: [
        /@api_view\(/gi,
        /class.*ViewSet/gi
      ]
    }
  ];

  // Vulnerability patterns
  private vulnerabilityPatterns = [
    {
      pattern: /(SELECT|INSERT|UPDATE|DELETE).*\$\{/gi,
      type: 'sql_injection' as const,
      severity: 'critical' as const,
      description: 'Potential SQL injection through template literals',
      remediation: 'Use parameterized queries or ORM'
    },
    {
      pattern: /innerHTML\s*=\s*[^;]+/gi,
      type: 'xss' as const,
      severity: 'high' as const,
      description: 'Potential XSS through innerHTML assignment',
      remediation: 'Use textContent or proper sanitization'
    },
    {
      pattern: /eval\s*\(/gi,
      type: 'injection' as const,
      severity: 'critical' as const,
      description: 'Code injection through eval()',
      remediation: 'Avoid eval() and use safer alternatives'
    },
    {
      pattern: /exec\s*\(/gi,
      type: 'injection' as const,
      severity: 'critical' as const,
      description: 'Command injection through exec()',
      remediation: 'Avoid exec() and use safer alternatives'
    },
    {
      pattern: /password\s*=\s*['"][^'"]+['"]/gi,
      type: 'information_disclosure' as const,
      severity: 'high' as const,
      description: 'Hardcoded password detected',
      remediation: 'Use environment variables or secure storage'
    }
  ];

  async scanFile(filePath: string): Promise<APIVulnerability[]> {
    this.endpoints = [];
    this.vulnerabilities = [];

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');

      // First pass: identify API endpoints
      await this.identifyEndpoints(lines, filePath);

      // Second pass: analyze endpoints for vulnerabilities
      await this.analyzeEndpoints(lines, filePath);

      // Third pass: generate security tests
      await this.generateSecurityTests();

    } catch (error) {
      console.error(`Error scanning API file ${filePath}:`, error);
    }

    return this.vulnerabilities;
  }

  private async identifyEndpoints(lines: string[], filePath: string) {
    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      // Skip comments and empty lines
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine === '') {
        return;
      }

      // Check for API endpoint patterns
      this.frameworkPatterns.forEach(framework => {
        framework.patterns.forEach(pattern => {
          const matches = trimmedLine.match(pattern);
          if (matches) {
            const endpoint = this.extractEndpoint(trimmedLine, lineNumber);
            if (endpoint) {
              this.endpoints.push(endpoint);
            }
          }
        });
      });
    });
  }

  private extractEndpoint(line: string, lineNumber: number): APIEndpoint | null {
    // Extract HTTP method and path
    const methodMatch = line.match(/(get|post|put|delete|patch)/i);
    const pathMatch = line.match(/['"`]([^'"`]+)['"`]/);

    if (methodMatch && pathMatch) {
      const method = methodMatch[1].toUpperCase();
      const path = pathMatch[1];

      return {
        method,
        path,
        line: lineNumber,
        parameters: this.extractParameters(line),
        authentication: this.checkAuthentication(line),
        authorization: this.checkAuthorization(line),
        rateLimit: this.checkRateLimit(line),
        inputValidation: this.checkInputValidation(line),
        outputSanitization: this.checkOutputSanitization(line)
      };
    }

    return null;
  }

  private extractParameters(line: string): APIParameter[] {
    const parameters: APIParameter[] = [];

    // Extract path parameters
    const pathParams = line.match(/:(\w+)/g);
    if (pathParams) {
      pathParams.forEach(param => {
        const name = param.substring(1);
        parameters.push({
          name,
          type: 'path',
          required: true,
          validation: [],
          sanitization: []
        });
      });
    }

    // Extract query parameters (simplified)
    const queryParams = line.match(/\?(\w+)/g);
    if (queryParams) {
      queryParams.forEach(param => {
        const name = param.substring(1);
        parameters.push({
          name,
          type: 'query',
          required: false,
          validation: [],
          sanitization: []
        });
      });
    }

    return parameters;
  }

  private checkAuthentication(line: string): boolean {
    const authPatterns = [
      /auth/gi,
      /middleware/gi,
      /@auth/gi,
      /requireAuth/gi,
      /isAuthenticated/gi
    ];

    return authPatterns.some(pattern => pattern.test(line));
  }

  private checkAuthorization(line: string): boolean {
    const authzPatterns = [
      /authorize/gi,
      /permission/gi,
      /role/gi,
      /@permission/gi,
      /hasRole/gi
    ];

    return authzPatterns.some(pattern => pattern.test(line));
  }

  private checkRateLimit(line: string): boolean {
    const rateLimitPatterns = [
      /rateLimit/gi,
      /throttle/gi,
      /@throttle/gi,
      /limiter/gi
    ];

    return rateLimitPatterns.some(pattern => pattern.test(line));
  }

  private checkInputValidation(line: string): boolean {
    const validationPatterns = [
      /validate/gi,
      /@validate/gi,
      /schema/gi,
      /joi/gi,
      /yup/gi
    ];

    return validationPatterns.some(pattern => pattern.test(line));
  }

  private checkOutputSanitization(line: string): boolean {
    const sanitizationPatterns = [
      /escape/gi,
      /sanitize/gi,
      /encode/gi,
      /@sanitize/gi
    ];

    return sanitizationPatterns.some(pattern => pattern.test(line));
  }

  private async analyzeEndpoints(lines: string[], filePath: string) {
    // Analyze each endpoint for vulnerabilities
    for (const endpoint of this.endpoints) {
      await this.analyzeEndpoint(endpoint, lines);
    }

    // Check for general vulnerability patterns
    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      this.vulnerabilityPatterns.forEach(pattern => {
        if (pattern.pattern.test(trimmedLine)) {
          this.vulnerabilities.push({
            type: pattern.type,
            endpoint: 'General',
            line: lineNumber,
            severity: pattern.severity,
            description: pattern.description,
            remediation: pattern.remediation
          });
        }
      });
    });
  }

  private async analyzeEndpoint(endpoint: APIEndpoint, lines: string[]) {
    // Check for missing authentication
    if (!endpoint.authentication) {
      this.vulnerabilities.push({
        type: 'authentication',
        endpoint: `${endpoint.method} ${endpoint.path}`,
        line: endpoint.line,
        severity: 'high',
        description: 'Endpoint lacks authentication',
        remediation: 'Implement authentication middleware or decorator',
        testCase: this.generateAuthTest(endpoint)
      });
    }

    // Check for missing authorization
    if (!endpoint.authorization) {
      this.vulnerabilities.push({
        type: 'authorization',
        endpoint: `${endpoint.method} ${endpoint.path}`,
        line: endpoint.line,
        severity: 'high',
        description: 'Endpoint lacks authorization checks',
        remediation: 'Implement authorization checks based on user roles',
        testCase: this.generateAuthzTest(endpoint)
      });
    }

    // Check for missing rate limiting
    if (!endpoint.rateLimit) {
      this.vulnerabilities.push({
        type: 'rate_limiting',
        endpoint: `${endpoint.method} ${endpoint.path}`,
        line: endpoint.line,
        severity: 'medium',
        description: 'Endpoint lacks rate limiting',
        remediation: 'Implement rate limiting to prevent abuse',
        testCase: this.generateRateLimitTest(endpoint)
      });
    }

    // Check for missing input validation
    if (!endpoint.inputValidation) {
      this.vulnerabilities.push({
        type: 'input_validation',
        endpoint: `${endpoint.method} ${endpoint.path}`,
        line: endpoint.line,
        severity: 'high',
        description: 'Endpoint lacks input validation',
        remediation: 'Implement input validation for all parameters',
        testCase: this.generateInputValidationTest(endpoint)
      });
    }

    // Check for missing output sanitization
    if (!endpoint.outputSanitization) {
      this.vulnerabilities.push({
        type: 'output_sanitization',
        endpoint: `${endpoint.method} ${endpoint.path}`,
        line: endpoint.line,
        severity: 'medium',
        description: 'Endpoint lacks output sanitization',
        remediation: 'Implement output sanitization to prevent XSS',
        testCase: this.generateOutputSanitizationTest(endpoint)
      });
    }
  }

  private generateAuthTest(endpoint: APIEndpoint): APITestCase {
    return {
      name: `Authentication Test - ${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      url: `http://localhost:3000${endpoint.path}`,
      headers: {},
      expectedResponse: 401,
      description: 'Test that unauthenticated requests are rejected',
      payload: 'No authentication header'
    };
  }

  private generateAuthzTest(endpoint: APIEndpoint): APITestCase {
    return {
      name: `Authorization Test - ${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      url: `http://localhost:3000${endpoint.path}`,
      headers: {
        'Authorization': 'Bearer valid-token-without-permissions'
      },
      expectedResponse: 403,
      description: 'Test that unauthorized requests are rejected',
      payload: 'Valid token but insufficient permissions'
    };
  }

  private generateRateLimitTest(endpoint: APIEndpoint): APITestCase {
    return {
      name: `Rate Limit Test - ${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      url: `http://localhost:3000${endpoint.path}`,
      headers: {},
      expectedResponse: 429,
      description: 'Test that rate limiting is enforced',
      payload: 'Multiple rapid requests'
    };
  }

  private generateInputValidationTest(endpoint: APIEndpoint): APITestCase {
    const maliciousPayload = this.generateMaliciousPayload(endpoint);
    
    return {
      name: `Input Validation Test - ${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      url: `http://localhost:3000${endpoint.path}`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: maliciousPayload,
      expectedResponse: 400,
      description: 'Test that malicious input is rejected',
      payload: JSON.stringify(maliciousPayload)
    };
  }

  private generateOutputSanitizationTest(endpoint: APIEndpoint): APITestCase {
    return {
      name: `Output Sanitization Test - ${endpoint.method} ${endpoint.path}`,
      method: endpoint.method,
      url: `http://localhost:3000${endpoint.path}`,
      headers: {},
      expectedResponse: 200,
      description: 'Test that output is properly sanitized',
      payload: 'Check response for unescaped HTML/script tags'
    };
  }

  private generateMaliciousPayload(endpoint: APIEndpoint): any {
    const payloads = {
      sql_injection: {
        username: "admin' OR '1'='1",
        password: "password' OR '1'='1"
      },
      xss: {
        name: "<script>alert('XSS')</script>",
        comment: "<img src=x onerror=alert('XSS')>"
      },
      command_injection: {
        filename: "test.txt; rm -rf /",
        command: "ls; cat /etc/passwd"
      },
      path_traversal: {
        file: "../../../etc/passwd",
        path: "....//....//....//etc/passwd"
      }
    };

    // Return appropriate payload based on endpoint type
    if (endpoint.path.includes('user') || endpoint.path.includes('auth')) {
      return payloads.sql_injection;
    } else if (endpoint.path.includes('comment') || endpoint.path.includes('post')) {
      return payloads.xss;
    } else if (endpoint.path.includes('file') || endpoint.path.includes('upload')) {
      return payloads.path_traversal;
    } else {
      return payloads.sql_injection;
    }
  }

  private async generateSecurityTests() {
    const testCategories = [
      {
        name: 'Authentication Tests',
        description: 'Tests for proper authentication implementation',
        category: 'authentication',
        severity: 'high' as const
      },
      {
        name: 'Authorization Tests',
        description: 'Tests for proper authorization checks',
        category: 'authorization',
        severity: 'high' as const
      },
      {
        name: 'Input Validation Tests',
        description: 'Tests for input validation and sanitization',
        category: 'input_validation',
        severity: 'high' as const
      },
      {
        name: 'Injection Tests',
        description: 'Tests for SQL injection, XSS, and command injection',
        category: 'injection',
        severity: 'critical' as const
      },
      {
        name: 'Rate Limiting Tests',
        description: 'Tests for rate limiting implementation',
        category: 'rate_limiting',
        severity: 'medium' as const
      }
    ];

    for (const category of testCategories) {
      const testCases = this.vulnerabilities
        .filter(v => v.type === category.category)
        .map(v => v.testCase)
        .filter(tc => tc !== undefined) as APITestCase[];

      if (testCases.length > 0) {
        this.securityTests.push({
          name: category.name,
          description: category.description,
          testCases,
          category: category.category,
          severity: category.severity
        });
      }
    }
  }

  async scanWorkspace(): Promise<APIVulnerability[]> {
    const allVulnerabilities: APIVulnerability[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,py,php,rb,go,java}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileVulnerabilities = await this.scanFile(file.fsPath);
        allVulnerabilities.push(...fileVulnerabilities);
      }

    } catch (error) {
      console.error('Error scanning workspace for API vulnerabilities:', error);
    }

    return allVulnerabilities;
  }

  generateAPISecurityReport(vulnerabilities: APIVulnerability[]): string {
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    const highVulns = vulnerabilities.filter(v => v.severity === 'high');
    const mediumVulns = vulnerabilities.filter(v => v.severity === 'medium');
    const lowVulns = vulnerabilities.filter(v => v.severity === 'low');

    return `
# API Security Analysis Report

## Executive Summary
- **Critical Vulnerabilities**: ${criticalVulns.length}
- **High Risk Vulnerabilities**: ${highVulns.length}
- **Medium Risk Vulnerabilities**: ${mediumVulns.length}
- **Low Risk Vulnerabilities**: ${lowVulns.length}

## Critical API Vulnerabilities (Fix Immediately)
${criticalVulns.map(vuln => `
### ${vuln.type.toUpperCase()} - ${vuln.endpoint}
- **Line**: ${vuln.line}
- **Description**: ${vuln.description}
- **Remediation**: ${vuln.remediation}
${vuln.testCase ? `- **Test Case**: ${vuln.testCase.name}` : ''}
`).join('')}

## High Risk API Vulnerabilities (Fix within 24 hours)
${highVulns.map(vuln => `
### ${vuln.type.toUpperCase()} - ${vuln.endpoint}
- **Line**: ${vuln.line}
- **Description**: ${vuln.description}
- **Remediation**: ${vuln.remediation}
`).join('')}

## Security Test Categories
${this.securityTests.map(test => `
### ${test.name}
- **Category**: ${test.category}
- **Severity**: ${test.severity}
- **Test Cases**: ${test.testCases.length}
- **Description**: ${test.description}
`).join('')}

## API Endpoints Analyzed
${this.endpoints.map(endpoint => `
- **${endpoint.method} ${endpoint.path}**
  - Authentication: ${endpoint.authentication ? '✅' : '❌'}
  - Authorization: ${endpoint.authorization ? '✅' : '❌'}
  - Rate Limiting: ${endpoint.rateLimit ? '✅' : '❌'}
  - Input Validation: ${endpoint.inputValidation ? '✅' : '❌'}
  - Output Sanitization: ${endpoint.outputSanitization ? '✅' : '❌'}
`).join('')}

## Recommendations
1. **Immediate**: Fix all critical vulnerabilities before deployment
2. **Short-term**: Address high-risk vulnerabilities within 24 hours
3. **Medium-term**: Implement comprehensive API security testing
4. **Long-term**: Establish API security best practices and training
`;
  }

  generateTestSuite(): string {
    const testSuite = {
      name: 'API Security Test Suite',
      description: 'Comprehensive security tests for API endpoints',
      tests: this.securityTests
    };

    return JSON.stringify(testSuite, null, 2);
  }
} 