import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface TaintSource {
  type: 'user_input' | 'network' | 'file' | 'database' | 'environment' | 'third_party';
  line: number;
  variable: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface TaintSink {
  type: 'sql_query' | 'eval' | 'file_write' | 'command_execution' | 'xss_output' | 'authentication';
  line: number;
  variable: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  path: TaintPath[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  confidence: number;
}

export interface TaintPath {
  line: number;
  variable: string;
  operation: 'assignment' | 'function_call' | 'method_call' | 'concatenation' | 'interpolation';
  context: string;
}

export interface DataFlowNode {
  id: string;
  line: number;
  variable: string;
  type: 'source' | 'sink' | 'propagation' | 'sanitization';
  value?: string;
  sanitized: boolean;
  sanitizationMethod?: string;
}

export interface DataFlowEdge {
  from: string;
  to: string;
  operation: string;
  line: number;
}

export class TaintAnalysisScanner {
  private sources: TaintSource[] = [];
  private sinks: TaintSink[] = [];
  private flows: TaintFlow[] = [];
  private dataFlowGraph: Map<string, DataFlowNode> = new Map();
  private dataFlowEdges: DataFlowEdge[] = [];

  // Source patterns
  private sourcePatterns = [
    {
      pattern: /(req\.body|req\.query|req\.params|req\.headers)/gi,
      type: 'user_input' as const,
      description: 'User input from HTTP request',
      severity: 'critical' as const
    },
    {
      pattern: /(document\.cookie|localStorage|sessionStorage)/gi,
      type: 'user_input' as const,
      description: 'Client-side user input',
      severity: 'high' as const
    },
    {
      pattern: /(fs\.readFileSync|fs\.readFile|readFile)/gi,
      type: 'file' as const,
      description: 'File system input',
      severity: 'medium' as const
    },
    {
      pattern: /(process\.env|process\.argv)/gi,
      type: 'environment' as const,
      description: 'Environment variable input',
      severity: 'medium' as const
    },
    {
      pattern: /(fetch|axios\.get|http\.get|https\.get)/gi,
      type: 'network' as const,
      description: 'Network input',
      severity: 'high' as const
    },
    {
      pattern: /(mysql\.query|pg\.query|sqlite\.query)/gi,
      type: 'database' as const,
      description: 'Database input',
      severity: 'medium' as const
    }
  ];

  // Sink patterns
  private sinkPatterns = [
    {
      pattern: /(eval|Function|setTimeout|setInterval)/gi,
      type: 'eval' as const,
      description: 'Code execution sink',
      severity: 'critical' as const
    },
    {
      pattern: /(exec|spawn|child_process)/gi,
      type: 'command_execution' as const,
      description: 'Command execution sink',
      severity: 'critical' as const
    },
    {
      pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)/gi,
      type: 'sql_query' as const,
      description: 'SQL query sink',
      severity: 'high' as const
    },
    {
      pattern: /(fs\.writeFile|fs\.writeFileSync|writeFile)/gi,
      type: 'file_write' as const,
      description: 'File write sink',
      severity: 'high' as const
    },
    {
      pattern: /(innerHTML|outerHTML|document\.write)/gi,
      type: 'xss_output' as const,
      description: 'XSS output sink',
      severity: 'high' as const
    },
    {
      pattern: /(bcrypt|hash|password|auth)/gi,
      type: 'authentication' as const,
      description: 'Authentication sink',
      severity: 'medium' as const
    }
  ];

  // Sanitization patterns
  private sanitizationPatterns = [
    /escape\(/gi,
    /encodeURIComponent\(/gi,
    /encodeURI\(/gi,
    /sanitize\(/gi,
    /validate\(/gi,
    /escapeHtml\(/gi,
    /sql\.escape\(/gi,
    /mysql\.escape\(/gi,
    /pg\.escape\(/gi
  ];

  async scanFile(filePath: string): Promise<TaintFlow[]> {
    this.sources = [];
    this.sinks = [];
    this.flows = [];
    this.dataFlowGraph.clear();
    this.dataFlowEdges = [];

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');

      // First pass: identify sources and sinks
      await this.identifySourcesAndSinks(lines, filePath);

      // Second pass: build data flow graph
      await this.buildDataFlowGraph(lines, filePath);

      // Third pass: trace taint flows
      await this.traceTaintFlows();

      // Fourth pass: analyze flows for vulnerabilities
      await this.analyzeFlows();

    } catch (error) {
      console.error(`Error in taint analysis for ${filePath}:`, error);
    }

    return this.flows;
  }

  private async identifySourcesAndSinks(lines: string[], filePath: string) {
    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      // Skip comments and empty lines
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine === '') {
        return;
      }

      // Identify sources
      this.sourcePatterns.forEach(pattern => {
        const matches = trimmedLine.match(pattern.pattern);
        if (matches) {
          const variable = this.extractVariable(trimmedLine);
          this.sources.push({
            type: pattern.type,
            line: lineNumber,
            variable,
            description: pattern.description,
            severity: pattern.severity
          });
        }
      });

      // Identify sinks
      this.sinkPatterns.forEach(pattern => {
        const matches = trimmedLine.match(pattern.pattern);
        if (matches) {
          const variable = this.extractVariable(trimmedLine);
          this.sinks.push({
            type: pattern.type,
            line: lineNumber,
            variable,
            description: pattern.description,
            severity: pattern.severity
          });
        }
      });
    });
  }

  private extractVariable(line: string): string {
    // Extract variable name from assignment or function call
    const assignmentMatch = line.match(/(\w+)\s*=/);
    if (assignmentMatch) {
      return assignmentMatch[1];
    }

    const functionMatch = line.match(/(\w+)\(/);
    if (functionMatch) {
      return functionMatch[1];
    }

    return 'unknown';
  }

  private async buildDataFlowGraph(lines: string[], filePath: string) {
    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      // Skip comments and empty lines
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine === '') {
        return;
      }

      // Track variable assignments
      this.trackVariableAssignments(trimmedLine, lineNumber);
      
      // Track function calls
      this.trackFunctionCalls(trimmedLine, lineNumber);
      
      // Track method calls
      this.trackMethodCalls(trimmedLine, lineNumber);
      
      // Track concatenations
      this.trackConcatenations(trimmedLine, lineNumber);
    });
  }

  private trackVariableAssignments(line: string, lineNumber: number) {
    const assignmentMatch = line.match(/(\w+)\s*=\s*(.+)/);
    if (assignmentMatch) {
      const variable = assignmentMatch[1];
      const value = assignmentMatch[2];

      // Check if this is a source
      const source = this.sources.find(s => s.line === lineNumber);
      if (source) {
        this.addDataFlowNode(variable, lineNumber, 'source', value, false);
      } else {
        // Check if value contains variables
        const variableMatch = value.match(/(\w+)/g);
        if (variableMatch) {
          variableMatch.forEach(varName => {
            if (varName !== variable && this.dataFlowGraph.has(varName)) {
              this.addDataFlowEdge(varName, variable, 'assignment', lineNumber);
            }
          });
        }
        this.addDataFlowNode(variable, lineNumber, 'propagation', value, false);
      }
    }
  }

  private trackFunctionCalls(line: string, lineNumber: number) {
    const functionMatch = line.match(/(\w+)\(([^)]*)\)/);
    if (functionMatch) {
      const functionName = functionMatch[1];
      const args = functionMatch[2];

      // Check if this is a sink
      const sink = this.sinks.find(s => s.line === lineNumber);
      if (sink) {
        this.addDataFlowNode(functionName, lineNumber, 'sink', args, false);
      }

      // Track argument variables
      const argVariables = args.match(/(\w+)/g);
      if (argVariables) {
        argVariables.forEach(argVar => {
          if (this.dataFlowGraph.has(argVar)) {
            this.addDataFlowEdge(argVar, functionName, 'function_call', lineNumber);
          }
        });
      }
    }
  }

  private trackMethodCalls(line: string, lineNumber: number) {
    const methodMatch = line.match(/(\w+)\.(\w+)\(([^)]*)\)/);
    if (methodMatch) {
      const object = methodMatch[1];
      const method = methodMatch[2];
      const args = methodMatch[3];

      // Check if this is a sink
      const sink = this.sinks.find(s => s.line === lineNumber);
      if (sink) {
        this.addDataFlowNode(`${object}.${method}`, lineNumber, 'sink', args, false);
      }

      // Track object and argument variables
      if (this.dataFlowGraph.has(object)) {
        this.addDataFlowEdge(object, `${object}.${method}`, 'method_call', lineNumber);
      }

      const argVariables = args.match(/(\w+)/g);
      if (argVariables) {
        argVariables.forEach(argVar => {
          if (this.dataFlowGraph.has(argVar)) {
            this.addDataFlowEdge(argVar, `${object}.${method}`, 'method_call', lineNumber);
          }
        });
      }
    }
  }

  private trackConcatenations(line: string, lineNumber: number) {
    const concatMatch = line.match(/(\w+)\s*=\s*(.+)\s*\+\s*(.+)/);
    if (concatMatch) {
      const resultVar = concatMatch[1];
      const leftOperand = concatMatch[2].trim();
      const rightOperand = concatMatch[3].trim();

      // Track dependencies
      [leftOperand, rightOperand].forEach(operand => {
        const operandMatch = operand.match(/(\w+)/);
        if (operandMatch && this.dataFlowGraph.has(operandMatch[1])) {
          this.addDataFlowEdge(operandMatch[1], resultVar, 'concatenation', lineNumber);
        }
      });

      this.addDataFlowNode(resultVar, lineNumber, 'propagation', `${leftOperand} + ${rightOperand}`, false);
    }
  }

  private addDataFlowNode(
    variable: string,
    line: number,
    type: 'source' | 'sink' | 'propagation' | 'sanitization',
    value?: string,
    sanitized: boolean = false,
    sanitizationMethod?: string
  ) {
    const nodeId = `${variable}_${line}`;
    this.dataFlowGraph.set(nodeId, {
      id: nodeId,
      line,
      variable,
      type,
      value,
      sanitized,
      sanitizationMethod
    });
  }

  private addDataFlowEdge(from: string, to: string, operation: string, line: number) {
    this.dataFlowEdges.push({
      from,
      to,
      operation,
      line
    });
  }

  private async traceTaintFlows() {
    // For each source, trace to all possible sinks
    for (const source of this.sources) {
      for (const sink of this.sinks) {
        const path = this.findPathFromSourceToSink(source, sink);
        if (path.length > 0) {
          const flow = this.createTaintFlow(source, sink, path);
          this.flows.push(flow);
        }
      }
    }
  }

  private findPathFromSourceToSink(source: TaintSource, sink: TaintSink): TaintPath[] {
    const path: TaintPath[] = [];
    const visited = new Set<string>();

    const dfs = (currentVar: string, targetVar: string, currentPath: TaintPath[]): boolean => {
      if (currentVar === targetVar) {
        path.push(...currentPath);
        return true;
      }

      if (visited.has(currentVar)) {
        return false;
      }

      visited.add(currentVar);

      // Find edges from current variable
      const edges = this.dataFlowEdges.filter(edge => edge.from === currentVar);
      
      for (const edge of edges) {
        const newPath = [...currentPath, {
          line: edge.line,
          variable: edge.to,
          operation: edge.operation as any,
          context: `From ${edge.from} to ${edge.to}`
        }];

        if (dfs(edge.to, targetVar, newPath)) {
          return true;
        }
      }

      return false;
    };

    dfs(source.variable, sink.variable, [{
      line: source.line,
      variable: source.variable,
      operation: 'source',
      context: `Source: ${source.description}`
    }]);

    return path;
  }

  private createTaintFlow(source: TaintSource, sink: TaintSink, path: TaintPath[]): TaintFlow {
    const severity = this.calculateFlowSeverity(source, sink);
    const description = this.generateFlowDescription(source, sink, path);
    const remediation = this.generateFlowRemediation(source, sink);
    const confidence = this.calculateFlowConfidence(path);

    return {
      source,
      sink,
      path,
      severity,
      description,
      remediation,
      confidence
    };
  }

  private calculateFlowSeverity(source: TaintSource, sink: TaintSink): 'critical' | 'high' | 'medium' | 'low' {
    // Critical combinations
    if (source.type === 'user_input' && sink.type === 'eval') return 'critical';
    if (source.type === 'user_input' && sink.type === 'command_execution') return 'critical';
    if (source.type === 'user_input' && sink.type === 'sql_query') return 'critical';

    // High combinations
    if (source.type === 'user_input' && sink.type === 'xss_output') return 'high';
    if (source.type === 'network' && sink.type === 'eval') return 'high';
    if (source.type === 'file' && sink.type === 'command_execution') return 'high';

    // Medium combinations
    if (source.type === 'environment' && sink.type === 'sql_query') return 'medium';
    if (source.type === 'database' && sink.type === 'file_write') return 'medium';

    return 'low';
  }

  private generateFlowDescription(source: TaintSource, sink: TaintSink, path: TaintPath[]): string {
    return `Data flows from ${source.description} (line ${source.line}) to ${sink.description} (line ${sink.line}) through ${path.length} operations. This creates a potential security vulnerability.`;
  }

  private generateFlowRemediation(source: TaintSource, sink: TaintSink): string {
    const remediations: { [key: string]: string } = {
      'eval': 'Validate and sanitize all input before using in eval() or use safer alternatives',
      'command_execution': 'Validate and sanitize all input before command execution',
      'sql_query': 'Use parameterized queries or ORM to prevent SQL injection',
      'xss_output': 'Sanitize and encode all output to prevent XSS attacks',
      'file_write': 'Validate file paths and content before writing to filesystem',
      'authentication': 'Use secure authentication methods and validate credentials'
    };

    return remediations[sink.type] || 'Implement proper input validation and sanitization';
  }

  private calculateFlowConfidence(path: TaintPath[]): number {
    let confidence = 0.5; // Base confidence

    // More steps in path increases confidence
    confidence += Math.min(path.length * 0.1, 0.3);

    // Check for sanitization in path
    const hasSanitization = path.some(step => 
      this.sanitizationPatterns.some(pattern => pattern.test(step.context))
    );

    if (hasSanitization) {
      confidence -= 0.2; // Reduce confidence if sanitization is present
    }

    return Math.min(Math.max(confidence, 0.1), 1.0);
  }

  private async analyzeFlows() {
    // Filter out flows with high confidence sanitization
    this.flows = this.flows.filter(flow => flow.confidence > 0.3);

    // Sort by severity and confidence
    this.flows.sort((a, b) => {
      const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
      const aScore = severityOrder[a.severity] * a.confidence;
      const bScore = severityOrder[b.severity] * b.confidence;
      return bScore - aScore;
    });
  }

  async scanWorkspace(): Promise<TaintFlow[]> {
    const allFlows: TaintFlow[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,php}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileFlows = await this.scanFile(file.fsPath);
        allFlows.push(...fileFlows);
      }

    } catch (error) {
      console.error('Error scanning workspace for taint flows:', error);
    }

    return allFlows;
  }

  generateTaintReport(flows: TaintFlow[]): string {
    const criticalFlows = flows.filter(f => f.severity === 'critical');
    const highFlows = flows.filter(f => f.severity === 'high');
    const mediumFlows = flows.filter(f => f.severity === 'medium');
    const lowFlows = flows.filter(f => f.severity === 'low');

    return `
# Taint Analysis Report

## Executive Summary
- **Critical Flows**: ${criticalFlows.length}
- **High Risk Flows**: ${highFlows.length}
- **Medium Risk Flows**: ${mediumFlows.length}
- **Low Risk Flows**: ${lowFlows.length}

## Critical Data Flows (Immediate Action Required)
${criticalFlows.map(flow => `
### ${flow.source.type} → ${flow.sink.type}
- **Source**: Line ${flow.source.line} - ${flow.source.description}
- **Sink**: Line ${flow.sink.line} - ${flow.sink.description}
- **Confidence**: ${(flow.confidence * 100).toFixed(1)}%
- **Path Length**: ${flow.path.length} operations
- **Description**: ${flow.description}
- **Remediation**: ${flow.remediation}
`).join('')}

## High Risk Data Flows (Fix within 24 hours)
${highFlows.map(flow => `
### ${flow.source.type} → ${flow.sink.type}
- **Source**: Line ${flow.source.line} - ${flow.source.description}
- **Sink**: Line ${flow.sink.line} - ${flow.sink.description}
- **Confidence**: ${(flow.confidence * 100).toFixed(1)}%
- **Remediation**: ${flow.remediation}
`).join('')}

## Data Flow Statistics
- **Total Flows Analyzed**: ${flows.length}
- **Average Path Length**: ${(flows.reduce((sum, f) => sum + f.path.length, 0) / flows.length).toFixed(1)}
- **Average Confidence**: ${(flows.reduce((sum, f) => sum + f.confidence, 0) / flows.length * 100).toFixed(1)}%

## Recommendations
1. **Immediate**: Fix all critical flows before deployment
2. **Short-term**: Address high-risk flows within 24 hours
3. **Medium-term**: Implement input validation and sanitization
4. **Long-term**: Establish secure coding practices and training
`;
  }
} 