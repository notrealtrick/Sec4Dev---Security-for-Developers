import * as vscode from 'vscode';
import { DependencyScanner } from './scanners/dependencyScanner';
import { SecretScanner } from './scanners/secretScanner';
import { OWASPScanner } from './scanners/owaspScanner';
import { AIScanner } from './scanners/aiScanner';
import { TerminalScanner } from './scanners/terminalScanner';
import { SecurityScoreCalculator } from './analytics/securityScore';
import { ProblemProvider } from './providers/problemProvider';
import { CodeActionProvider } from './providers/codeActionProvider';
import { HoverProvider } from './providers/hoverProvider';
import { CLIScanner } from './cli/cliScanner';
import { GitHubAction } from './integrations/githubAction';
import { DockerfileScanner, IaCScanner } from './scanners/dockerfileScanner';
import { RiskPrioritizationScanner } from './scanners/riskPrioritizationScanner';
import { TaintAnalysisScanner } from './scanners/taintAnalysisScanner';
import { APISecurityScanner } from './scanners/apiSecurityScanner';
import { TrainingModule } from './scanners/trainingModule';

interface ScanResult {
  evalCount: number;
  suspiciousPatterns: SuspiciousPattern[];
  filePath: string;
  lineNumbers: number[];
  dependencyVulnerabilities?: DependencyVulnerability[];
  secrets?: Secret[];
  owaspIssues?: OWASPIssue[];
  terminalCommands?: TerminalCommand[];
  aiAnalysis?: AIAnalysis;
  securityScore?: number;
  dockerfileIssues?: any[];
  iacIssues?: any[];
  taintFlows?: any[];
  apiVulnerabilities?: any[];
  prioritizedIssues?: any[];
}

interface SuspiciousPattern {
  type: 'xor' | 'base64' | 'obfuscated' | 'dynamic_code' | 'sql_injection' | 'xss' | 'csrf';
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  suggestion?: string;
}

interface DependencyVulnerability {
  package: string;
  version: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  cve?: string;
  fixVersion?: string;
}

interface Secret {
  type: 'api_key' | 'password' | 'token' | 'private_key' | 'database_url';
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  suggestion: string;
}

interface OWASPIssue {
  category: string;
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  owaspReference: string;
}

interface TerminalCommand {
  type: 'base64_encoded' | 'powershell_encoded' | 'reverse_shell' | 'file_download' | 'privilege_escalation' | 'network_scan' | 'data_exfiltration' | 'obfuscated_command';
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  suggestion: string;
  decodedCommand?: string;
}

interface AIAnalysis {
  intent: 'malicious' | 'suspicious' | 'benign';
  confidence: number;
  explanation: string;
  riskLevel: 'high' | 'medium' | 'low';
}

export function activate(context: vscode.ExtensionContext) {
  console.log('Sec4Dev - Security for Developers is now active!');

  // Initialize scanners
  const dependencyScanner = new DependencyScanner();
  const secretScanner = new SecretScanner();
  const owaspScanner = new OWASPScanner();
  const aiScanner = new AIScanner();
  const terminalScanner = new TerminalScanner();
  const securityScore = new SecurityScoreCalculator();
  const cliScanner = new CLIScanner();
  const githubAction = new GitHubAction();
  
  // Initialize new scanners
  const dockerfileScanner = new DockerfileScanner();
  const iacScanner = new IaCScanner();
  const riskPrioritizationScanner = new RiskPrioritizationScanner();
  const taintAnalysisScanner = new TaintAnalysisScanner();
  const apiSecurityScanner = new APISecurityScanner();
  const trainingModule = new TrainingModule();

  // Initialize providers
  const problemProvider = new ProblemProvider();
  const codeActionProvider = new CodeActionProvider();
  const hoverProvider = new HoverProvider();

  // Register commands
  let scanDocument = vscode.commands.registerCommand('sec4dev.scanDocument', async () => {
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      const result = await comprehensiveScan(editor.document);
      showResults(result);
    } else {
      vscode.window.showInformationMessage('No active document to scan.');
    }
  });

  let scanWorkspace = vscode.commands.registerCommand('sec4dev.scanWorkspace', async () => {
    const results = await scanWorkspaceComprehensive();
    showWorkspaceResults(results);
  });

  let scanDependencies = vscode.commands.registerCommand('sec4dev.scanDependencies', async () => {
    const vulnerabilities = await dependencyScanner.scan();
    showDependencyResults(vulnerabilities);
  });

  let scanSecrets = vscode.commands.registerCommand('sec4dev.scanSecrets', async () => {
    const secrets = await secretScanner.scan();
    showSecretResults(secrets);
  });

  let owaspScan = vscode.commands.registerCommand('sec4dev.owaspScan', async () => {
    const issues = await owaspScanner.scan();
    showOWASPResults(issues);
  });

  let terminalScan = vscode.commands.registerCommand('sec4dev.terminalScan', async () => {
    const commands = await terminalScanner.scan();
    showTerminalResults(commands);
  });

  let securityScoreCmd = vscode.commands.registerCommand('sec4dev.securityScore', async () => {
    const score = await securityScore.calculateScore();
    showSecurityScoreDashboard(score);
  });

  let cliScan = vscode.commands.registerCommand('sec4dev.cliScan', async () => {
    const result = await cliScanner.scan();
    showCLIResults(result);
  });

  // New commands for advanced features
  let dockerfileScan = vscode.commands.registerCommand('sec4dev.dockerfileScan', async () => {
    const issues = await dockerfileScanner.scanWorkspace();
    showDockerfileResults(issues);
  });

  let iacScan = vscode.commands.registerCommand('sec4dev.iacScan', async () => {
    const issues = await iacScanner.scanWorkspace();
    showIaCResults(issues);
  });

  let taintAnalysis = vscode.commands.registerCommand('sec4dev.taintAnalysis', async () => {
    const flows = await taintAnalysisScanner.scanWorkspace();
    showTaintAnalysisResults(flows);
  });

  let apiSecurityScan = vscode.commands.registerCommand('sec4dev.apiSecurityScan', async () => {
    const vulnerabilities = await apiSecurityScanner.scanWorkspace();
    showAPISecurityResults(vulnerabilities);
  });

  let riskPrioritization = vscode.commands.registerCommand('sec4dev.riskPrioritization', async () => {
    const allIssues = await getAllIssues();
    const prioritizedIssues = await riskPrioritizationScanner.prioritizeIssues(allIssues);
    showRiskPrioritizationResults(prioritizedIssues);
  });

  let securityTraining = vscode.commands.registerCommand('sec4dev.securityTraining', async () => {
    const lessons = await trainingModule.getLessons();
    showSecurityTraining(lessons);
  });

  context.subscriptions.push(
    scanDocument, 
    scanWorkspace, 
    scanDependencies, 
    scanSecrets, 
    owaspScan, 
    terminalScan,
    securityScoreCmd, 
    cliScan,
    dockerfileScan,
    iacScan,
    taintAnalysis,
    apiSecurityScan,
    riskPrioritization,
    securityTraining
  );

  // Register providers
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('*', codeActionProvider),
    vscode.languages.registerHoverProvider('*', hoverProvider),
    vscode.window.registerTreeDataProvider('sec4devProblems', problemProvider)
  );

  // Real-time scanning
  const config = vscode.workspace.getConfiguration('sec4dev');
  if (config.get('enableRealTimeScanning')) {
    const changeListener = vscode.workspace.onDidChangeTextDocument(async (event) => {
      if (event.document === vscode.window.activeTextEditor?.document) {
        const result = await comprehensiveScan(event.document);
        if (result.evalCount > 0 || result.suspiciousPatterns.length > 0) {
          showRealTimeWarning(result);
        }
      }
    });
    context.subscriptions.push(changeListener);
  }

  // Auto-scan on save
  if (config.get('autoScanOnSave')) {
    const saveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
      const result = await comprehensiveScan(document);
      updateProblems(result);
    });
    context.subscriptions.push(saveListener);
  }

  // Auto-scan before commit
  if (config.get('autoScanOnCommit')) {
    const gitListener = vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (event.affectsConfiguration('git')) {
        const results = await scanWorkspaceComprehensive();
        const score = await securityScore.calculateScore();
        if (score.score < config.get('securityScoreThreshold', 70)) {
          vscode.window.showWarningMessage(
            `Security score is ${score.score}/100. Consider fixing issues before committing.`
          );
        }
      }
    });
    context.subscriptions.push(gitListener);
  }
}

function scanDocumentForEval(document: vscode.TextDocument): ScanResult {
  const text = document.getText();
  const lines = text.split('\n');
  const result: ScanResult = {
    evalCount: 0,
    suspiciousPatterns: [],
    filePath: document.fileName,
    lineNumbers: []
  };

  // Patterns to detect
  const evalPatterns = [
    /\beval\s*\(/gi,
    /\beval\s*\(/gi,
    /\bFunction\s*\(\s*["'][^"']*["']\s*\)/gi,
    /\bsetTimeout\s*\(\s*["'][^"']*["']/gi,
    /\bsetInterval\s*\(\s*["'][^"']*["']/gi
  ];

  const xorPatterns = [
    /\bXOR\b/gi,
    /\bxor\b/gi,
    /\b\^[\s\S]*\b/gi, // XOR operator usage
    /\bdecrypt\b/gi,
    /\bencrypt\b/gi
  ];

  const base64Patterns = [
    /\batob\s*\(/gi,
    /\bbtoa\s*\(/gi,
    /\bBuffer\.from\s*\([^)]*,\s*['"]base64['"]/gi,
    /\bnew\s+TextDecoder\s*\(/gi,
    /\bnew\s+TextEncoder\s*\(/gi
  ];

  const obfuscatedPatterns = [
    /\bunescape\s*\(/gi,
    /\bdecodeURIComponent\s*\(/gi,
    /\bString\.fromCharCode\s*\(/gi,
    /\bcharCodeAt\s*\(/gi,
    /\bcharAt\s*\(/gi
  ];

  const dynamicCodePatterns = [
    /\bnew\s+Function\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bchild_process\b/gi
  ];

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmedLine = line.trim();

    // Skip comments and empty lines
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine.startsWith('*') || trimmedLine === '') {
      return;
    }

    // Check for eval patterns
    evalPatterns.forEach(pattern => {
      if (pattern.test(line)) {
        result.evalCount++;
        result.lineNumbers.push(lineNumber);
        
        result.suspiciousPatterns.push({
          type: 'dynamic_code',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Direct eval() usage detected - HIGH SECURITY RISK!'
        });
      }
    });

    // Check for XOR patterns
    xorPatterns.forEach(pattern => {
      if (pattern.test(line)) {
        result.suspiciousPatterns.push({
          type: 'xor',
          line: lineNumber,
          code: line.trim(),
          severity: 'medium',
          description: 'XOR operation detected - potential obfuscation'
        });
      }
    });

    // Check for base64 patterns
    base64Patterns.forEach(pattern => {
      if (pattern.test(line)) {
        result.suspiciousPatterns.push({
          type: 'base64',
          line: lineNumber,
          code: line.trim(),
          severity: 'medium',
          description: 'Base64 encoding/decoding detected - potential data hiding'
        });
      }
    });

    // Check for obfuscated patterns
    obfuscatedPatterns.forEach(pattern => {
      if (pattern.test(line)) {
        result.suspiciousPatterns.push({
          type: 'obfuscated',
          line: lineNumber,
          code: line.trim(),
          severity: 'low',
          description: 'Potential code obfuscation detected'
        });
      }
    });

    // Check for dynamic code execution patterns
    dynamicCodePatterns.forEach(pattern => {
      if (pattern.test(line)) {
        result.suspiciousPatterns.push({
          type: 'dynamic_code',
          line: lineNumber,
          code: line.trim(),
          severity: 'high',
          description: 'Dynamic code execution detected - SECURITY RISK!'
        });
      }
    });
  });

  return result;
}

async function comprehensiveScan(document: vscode.TextDocument): Promise<ScanResult> {
  const config = vscode.workspace.getConfiguration('sec4dev');
  const result: ScanResult = {
    evalCount: 0,
    suspiciousPatterns: [],
    filePath: document.fileName,
    lineNumbers: []
  };

  // Basic security scan
  const basicResult = scanDocumentForEval(document);
  result.evalCount = basicResult.evalCount;
  result.suspiciousPatterns = basicResult.suspiciousPatterns;
  result.lineNumbers = basicResult.lineNumbers;

  // Dependency scan
  if (config.get('enableDependencyScanning')) {
    const dependencyScanner = new DependencyScanner();
    result.dependencyVulnerabilities = await dependencyScanner.scanFile(document.fileName);
  }

  // Secret scan
  if (config.get('enableSecretScanning')) {
    const secretScanner = new SecretScanner();
    result.secrets = await secretScanner.scanFile(document.fileName);
  }

  // OWASP scan
  if (config.get('enableOWASPScanning')) {
    const owaspScanner = new OWASPScanner();
    result.owaspIssues = await owaspScanner.scanFile(document.fileName);
  }

  // Terminal command scan
  if (config.get('enableTerminalScanning', true)) {
    const terminalScanner = new TerminalScanner();
    result.terminalCommands = await terminalScanner.scanFile(document.fileName);
  }

  // AI analysis
  if (config.get('enableAIAnalysis')) {
    const aiScanner = new AIScanner();
    result.aiAnalysis = await aiScanner.analyze(document.getText());
  }

  // Calculate security score
  const securityScore = new SecurityScoreCalculator();
  result.securityScore = await securityScore.calculateFileScore(result);

  return result;
}

async function scanWorkspaceComprehensive(): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  const files = await vscode.workspace.findFiles(
    '**/*.{js,ts,jsx,tsx,py,php,json,yaml,yml,xml}', 
    '**/node_modules/**'
  );

  for (const file of files) {
    try {
      const document = await vscode.workspace.openTextDocument(file);
      const result = await comprehensiveScan(document);
      if (result.evalCount > 0 || result.suspiciousPatterns.length > 0 || 
          result.dependencyVulnerabilities?.length || result.secrets?.length || 
          result.owaspIssues?.length) {
        results.push(result);
      }
    } catch (error) {
      console.error(`Error scanning file ${file.fsPath}:`, error);
    }
  }

  return results;
}

function updateProblems(result: ScanResult) {
  const problems: vscode.Diagnostic[] = [];
  
  // Add eval issues
  result.lineNumbers.forEach(line => {
    problems.push({
      range: new vscode.Range(line - 1, 0, line - 1, 100),
      message: 'Eval() usage detected - HIGH SECURITY RISK!',
      severity: vscode.DiagnosticSeverity.Error,
      source: 'Sec4Dev'
    });
  });

  // Add suspicious patterns
  result.suspiciousPatterns.forEach(pattern => {
    problems.push({
      range: new vscode.Range(pattern.line - 1, 0, pattern.line - 1, 100),
      message: pattern.description,
      severity: pattern.severity === 'high' ? vscode.DiagnosticSeverity.Error : 
                pattern.severity === 'medium' ? vscode.DiagnosticSeverity.Warning : 
                vscode.DiagnosticSeverity.Information,
      source: 'Sec4Dev'
    });
  });

  // Add secrets
  result.secrets?.forEach(secret => {
    problems.push({
      range: new vscode.Range(secret.line - 1, 0, secret.line - 1, 100),
      message: `Secret detected: ${secret.description}`,
      severity: vscode.DiagnosticSeverity.Error,
      source: 'Sec4Dev'
    });
  });

  // Add OWASP issues
  result.owaspIssues?.forEach(issue => {
    problems.push({
      range: new vscode.Range(issue.line - 1, 0, issue.line - 1, 100),
      message: `OWASP ${issue.category}: ${issue.description}`,
      severity: issue.severity === 'high' ? vscode.DiagnosticSeverity.Error : 
                issue.severity === 'medium' ? vscode.DiagnosticSeverity.Warning : 
                vscode.DiagnosticSeverity.Information,
      source: 'Sec4Dev'
    });
  });

  // Add terminal commands
  result.terminalCommands?.forEach(command => {
    const message = command.decodedCommand 
      ? `Terminal Command (${command.type}): ${command.description} - Decoded: ${command.decodedCommand}`
      : `Terminal Command (${command.type}): ${command.description}`;
    
    problems.push({
      range: new vscode.Range(command.line - 1, 0, command.line - 1, 100),
      message,
      severity: command.severity === 'high' ? vscode.DiagnosticSeverity.Error : 
                command.severity === 'medium' ? vscode.DiagnosticSeverity.Warning : 
                vscode.DiagnosticSeverity.Information,
      source: 'Sec4Dev'
    });
  });

  // Update problems view
  const collection = vscode.languages.createDiagnosticCollection('sec4dev');
  collection.set(vscode.Uri.file(result.filePath), problems);
}

function showResults(result: ScanResult) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devResults',
    'Sec4Dev Security Results',
    vscode.ViewColumn.One,
    {}
  );

  const highRiskCount = result.suspiciousPatterns.filter(p => p.severity === 'high').length;
  const mediumRiskCount = result.suspiciousPatterns.filter(p => p.severity === 'medium').length;
  const lowRiskCount = result.suspiciousPatterns.filter(p => p.severity === 'low').length;

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sec4Dev Security Results</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat { background: #fff; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }
        .high-risk { color: #d32f2f; font-weight: bold; }
        .medium-risk { color: #f57c00; font-weight: bold; }
        .low-risk { color: #388e3c; font-weight: bold; }
        .pattern { background: #fff; padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .pattern.high { border-left-color: #d32f2f; }
        .pattern.medium { border-left-color: #f57c00; }
        .pattern.low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ Sec4Dev Security Scan Results</h1>
        <p><strong>File:</strong> ${result.filePath}</p>
      </div>
      
      <div class="stats">
        <div class="stat">
          <h3>🚨 Eval Functions</h3>
          <p class="high-risk">${result.evalCount}</p>
        </div>
        <div class="stat">
          <h3>⚠️ High Risk</h3>
          <p class="high-risk">${highRiskCount}</p>
        </div>
        <div class="stat">
          <h3>⚠️ Medium Risk</h3>
          <p class="medium-risk">${mediumRiskCount}</p>
        </div>
        <div class="stat">
          <h3>ℹ️ Low Risk</h3>
          <p class="low-risk">${lowRiskCount}</p>
        </div>
      </div>

      <h2>Suspicious Patterns Found:</h2>
      ${result.suspiciousPatterns.map(pattern => `
        <div class="pattern ${pattern.severity}">
          <h4>Line ${pattern.line} - ${pattern.type.toUpperCase()}</h4>
          <p><strong>${pattern.description}</strong></p>
          <div class="code">${pattern.code}</div>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showWorkspaceResults(results: ScanResult[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devWorkspaceResults',
    'Sec4Dev Workspace Security Scan',
    vscode.ViewColumn.One,
    {}
  );

  const totalEvalCount = results.reduce((sum, r) => sum + r.evalCount, 0);
  const totalHighRisk = results.reduce((sum, r) => sum + r.suspiciousPatterns.filter(p => p.severity === 'high').length, 0);
  const totalMediumRisk = results.reduce((sum, r) => sum + r.suspiciousPatterns.filter(p => p.severity === 'medium').length, 0);
  const totalLowRisk = results.reduce((sum, r) => sum + r.suspiciousPatterns.filter(p => p.severity === 'low').length, 0);

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sec4Dev Workspace Security Scan</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat { background: #fff; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }
        .high-risk { color: #d32f2f; font-weight: bold; }
        .medium-risk { color: #f57c00; font-weight: bold; }
        .low-risk { color: #388e3c; font-weight: bold; }
        .file-result { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; }
        .file-path { font-weight: bold; color: #1976d2; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ Sec4Dev Workspace Security Scan</h1>
        <p>Scanned ${results.length} files</p>
      </div>
      
      <div class="stats">
        <div class="stat">
          <h3>🚨 Total Eval Functions</h3>
          <p class="high-risk">${totalEvalCount}</p>
        </div>
        <div class="stat">
          <h3>⚠️ High Risk Issues</h3>
          <p class="high-risk">${totalHighRisk}</p>
        </div>
        <div class="stat">
          <h3>⚠️ Medium Risk Issues</h3>
          <p class="medium-risk">${totalMediumRisk}</p>
        </div>
        <div class="stat">
          <h3>ℹ️ Low Risk Issues</h3>
          <p class="low-risk">${totalLowRisk}</p>
        </div>
      </div>

      <h2>Files with Issues:</h2>
      ${results.map(result => `
        <div class="file-result">
          <div class="file-path">${result.filePath}</div>
          <p>Eval functions: ${result.evalCount}</p>
          <p>Suspicious patterns: ${result.suspiciousPatterns.length}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showRealTimeWarning(result: ScanResult) {
  const config = vscode.workspace.getConfiguration('sec4dev');
  if (!config.get('showWarnings')) {
    return;
  }

  const highRiskCount = result.suspiciousPatterns.filter(p => p.severity === 'high').length;
  
  if (result.evalCount > 0 || highRiskCount > 0) {
    vscode.window.showWarningMessage(
      `🚨 Sec4Dev Security Alert: ${result.evalCount} eval() functions and ${highRiskCount} high-risk patterns detected!`,
      'View Details'
    ).then(selection => {
      if (selection === 'View Details') {
        showResults(result);
      }
    });
  }
}

function showDependencyResults(vulnerabilities: DependencyVulnerability[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devDependencies',
    'Sec4Dev Dependency Vulnerabilities',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Dependency Vulnerabilities</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerability { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ Dependency Vulnerabilities Found</h1>
        <p>Total: ${vulnerabilities.length} vulnerabilities</p>
      </div>
      
      ${vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity}">
          <h3>${vuln.package}@${vuln.version}</h3>
          <p><strong>Severity:</strong> ${vuln.severity.toUpperCase()}</p>
          <p><strong>Description:</strong> ${vuln.description}</p>
          ${vuln.cve ? `<p><strong>CVE:</strong> ${vuln.cve}</p>` : ''}
          ${vuln.fixVersion ? `<p><strong>Fix Version:</strong> ${vuln.fixVersion}</p>` : ''}
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showSecretResults(secrets: Secret[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devSecrets',
    'Sec4Dev Secrets Detection',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Secrets Detection</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .secret { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #d32f2f; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🔐 Secrets Detection Results</h1>
        <p>Found ${secrets.length} potential secrets</p>
      </div>
      
      ${secrets.map(secret => `
        <div class="secret">
          <h3>${secret.type.toUpperCase()} - Line ${secret.line}</h3>
          <p><strong>Description:</strong> ${secret.description}</p>
          <div class="code">${secret.code}</div>
          <p><strong>Suggestion:</strong> ${secret.suggestion}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showOWASPResults(issues: OWASPIssue[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devOWASP',
    'Sec4Dev OWASP Top 10 Scan',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>OWASP Top 10 Vulnerabilities</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .issue { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .high { border-left-color: #d32f2f; }
        .medium { border-left-color: #f57c00; }
        .low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ OWASP Top 10 Vulnerabilities</h1>
        <p>Found ${issues.length} OWASP issues</p>
      </div>
      
      ${issues.map(issue => `
        <div class="issue ${issue.severity}">
          <h3>${issue.category} - Line ${issue.line}</h3>
          <p><strong>Description:</strong> ${issue.description}</p>
          <div class="code">${issue.code}</div>
          <p><strong>Remediation:</strong> ${issue.remediation}</p>
          <p><strong>OWASP Reference:</strong> ${issue.owaspReference}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showTerminalResults(commands: TerminalCommand[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devTerminal',
    'Sec4Dev Terminal Command Analysis',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Terminal Command Analysis</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .command { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .high { border-left-color: #d32f2f; }
        .medium { border-left-color: #f57c00; }
        .low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
        .decoded { background: #fff3cd; padding: 8px; border-radius: 3px; font-family: monospace; border: 1px solid #ffeaa7; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🖥️ Terminal Command Analysis</h1>
        <p>Found ${commands.length} suspicious terminal commands</p>
      </div>
      
      ${commands.map(command => `
        <div class="command ${command.severity}">
          <h3>${command.type.replace(/_/g, ' ').toUpperCase()} - Line ${command.line}</h3>
          <p><strong>Description:</strong> ${command.description}</p>
          <div class="code">${command.code}</div>
          ${command.decodedCommand ? `<div class="decoded"><strong>Decoded Command:</strong> ${command.decodedCommand}</div>` : ''}
          <p><strong>Suggestion:</strong> ${command.suggestion}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showSecurityScoreDashboard(score: any) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devScore',
    'Sec4Dev Security Score Dashboard',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Security Score Dashboard</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .score { font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }
        .excellent { color: #388e3c; }
        .good { color: #fbc02d; }
        .poor { color: #d32f2f; }
        .metric { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ Security Score Dashboard</h1>
      </div>
      
      <div class="score ${score.level}">${score.score}/100</div>
      
      <div class="metric">
        <h3>Overall Score: ${score.score}/100</h3>
        <p><strong>Level:</strong> ${score.level}</p>
        <p><strong>Recommendations:</strong> ${score.recommendations.join(', ')}</p>
      </div>
      
      <div class="metric">
        <h3>Weekly Progress</h3>
        <p><strong>Previous Score:</strong> ${score.previousScore}/100</p>
        <p><strong>Improvement:</strong> ${score.improvement}%</p>
      </div>
    </body>
    </html>
  `;
}

function showCLIResults(result: any) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devCLI',
    'Sec4Dev CLI Scan Results',
    vscode.ViewColumn.One,
    {}
  );

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>CLI Scan Results</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .result { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🛡️ CLI Security Scan Results</h1>
      </div>
      
      <div class="result">
        <h3>Scan Summary</h3>
        <p><strong>Files Scanned:</strong> ${result.filesScanned}</p>
        <p><strong>Issues Found:</strong> ${result.issuesFound}</p>
        <p><strong>Security Score:</strong> ${result.securityScore}/100</p>
      </div>
      
      <div class="result">
        <h3>Command Used</h3>
        <code>sec4dev scan --all</code>
      </div>
    </body>
    </html>
  `;
}

// New result display functions
function showDockerfileResults(issues: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devDockerfile',
    'Sec4Dev Dockerfile Security Scan',
    vscode.ViewColumn.One,
    {}
  );

  const criticalIssues = issues.filter(i => i.severity === 'critical');
  const highIssues = issues.filter(i => i.severity === 'high');
  const mediumIssues = issues.filter(i => i.severity === 'medium');
  const lowIssues = issues.filter(i => i.severity === 'low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Dockerfile Security Scan</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .issue { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🐳 Dockerfile Security Scan Results</h1>
        <p>Found ${issues.length} security issues in Dockerfiles</p>
      </div>
      
      <div class="stats">
        <p><strong>Critical:</strong> ${criticalIssues.length} | <strong>High:</strong> ${highIssues.length} | <strong>Medium:</strong> ${mediumIssues.length} | <strong>Low:</strong> ${lowIssues.length}</p>
      </div>
      
      ${issues.map(issue => `
        <div class="issue ${issue.severity}">
          <h3>${issue.type.toUpperCase()} - Line ${issue.line}</h3>
          <p><strong>Description:</strong> ${issue.description}</p>
          <div class="code">${issue.code}</div>
          <p><strong>Remediation:</strong> ${issue.remediation}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showIaCResults(issues: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devIaC',
    'Sec4Dev Infrastructure as Code Security Scan',
    vscode.ViewColumn.One,
    {}
  );

  const criticalIssues = issues.filter(i => i.severity === 'critical');
  const highIssues = issues.filter(i => i.severity === 'high');
  const mediumIssues = issues.filter(i => i.severity === 'medium');
  const lowIssues = issues.filter(i => i.severity === 'low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>IaC Security Scan</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .issue { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🏗️ Infrastructure as Code Security Scan</h1>
        <p>Found ${issues.length} security issues in IaC files</p>
      </div>
      
      <div class="stats">
        <p><strong>Critical:</strong> ${criticalIssues.length} | <strong>High:</strong> ${highIssues.length} | <strong>Medium:</strong> ${mediumIssues.length} | <strong>Low:</strong> ${lowIssues.length}</p>
      </div>
      
      ${issues.map(issue => `
        <div class="issue ${issue.severity}">
          <h3>${issue.type.toUpperCase()} - Line ${issue.line}</h3>
          <p><strong>Description:</strong> ${issue.description}</p>
          <div class="code">${issue.code}</div>
          <p><strong>Remediation:</strong> ${issue.remediation}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showTaintAnalysisResults(flows: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devTaint',
    'Sec4Dev Taint Analysis Results',
    vscode.ViewColumn.One,
    {}
  );

  const criticalFlows = flows.filter(f => f.severity === 'critical');
  const highFlows = flows.filter(f => f.severity === 'high');
  const mediumFlows = flows.filter(f => f.severity === 'medium');
  const lowFlows = flows.filter(f => f.severity === 'low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Taint Analysis Results</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .flow { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .path { background: #f9f9f9; padding: 10px; margin: 5px 0; border-radius: 3px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🔍 Taint Analysis Results</h1>
        <p>Found ${flows.length} data flow vulnerabilities</p>
      </div>
      
      <div class="stats">
        <p><strong>Critical Flows:</strong> ${criticalFlows.length} | <strong>High Risk:</strong> ${highFlows.length} | <strong>Medium Risk:</strong> ${mediumFlows.length} | <strong>Low Risk:</strong> ${lowFlows.length}</p>
      </div>
      
      ${flows.map(flow => `
        <div class="flow ${flow.severity}">
          <h3>${flow.source.type} → ${flow.sink.type}</h3>
          <p><strong>Source:</strong> Line ${flow.source.line} - ${flow.source.description}</p>
          <p><strong>Sink:</strong> Line ${flow.sink.line} - ${flow.sink.description}</p>
          <p><strong>Confidence:</strong> ${(flow.confidence * 100).toFixed(1)}%</p>
          <p><strong>Description:</strong> ${flow.description}</p>
          <p><strong>Remediation:</strong> ${flow.remediation}</p>
          <div class="path">
            <strong>Data Flow Path:</strong>
            ${flow.path.map(step => `<div>Line ${step.line}: ${step.operation} - ${step.context}</div>`).join('')}
          </div>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showAPISecurityResults(vulnerabilities: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devAPI',
    'Sec4Dev API Security Scan Results',
    vscode.ViewColumn.One,
    {}
  );

  const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
  const highVulns = vulnerabilities.filter(v => v.severity === 'high');
  const mediumVulns = vulnerabilities.filter(v => v.severity === 'medium');
  const lowVulns = vulnerabilities.filter(v => v.severity === 'low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>API Security Scan</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vuln { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .code { background: #f5f5f5; padding: 8px; border-radius: 3px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🔌 API Security Scan Results</h1>
        <p>Found ${vulnerabilities.length} API security vulnerabilities</p>
      </div>
      
      <div class="stats">
        <p><strong>Critical:</strong> ${criticalVulns.length} | <strong>High:</strong> ${highVulns.length} | <strong>Medium:</strong> ${mediumVulns.length} | <strong>Low:</strong> ${lowVulns.length}</p>
      </div>
      
      ${vulnerabilities.map(vuln => `
        <div class="vuln ${vuln.severity}">
          <h3>${vuln.type.toUpperCase()} - ${vuln.endpoint}</h3>
          <p><strong>Line:</strong> ${vuln.line}</p>
          <p><strong>Description:</strong> ${vuln.description}</p>
          <p><strong>Remediation:</strong> ${vuln.remediation}</p>
          ${vuln.testCase ? `<p><strong>Test Case:</strong> ${vuln.testCase.name}</p>` : ''}
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

async function getAllIssues(): Promise<any[]> {
  const allIssues: any[] = [];
  
  // Collect issues from all scanners
  const dependencyScanner = new DependencyScanner();
  const secretScanner = new SecretScanner();
  const owaspScanner = new OWASPScanner();
  const terminalScanner = new TerminalScanner();
  
  try {
    const dependencies = await dependencyScanner.scan();
    const secrets = await secretScanner.scan();
    const owaspIssues = await owaspScanner.scan();
    const terminalCommands = await terminalScanner.scan();
    
    allIssues.push(...dependencies, ...secrets, ...owaspIssues, ...terminalCommands);
  } catch (error) {
    console.error('Error collecting all issues:', error);
  }
  
  return allIssues;
}

function showRiskPrioritizationResults(prioritizedIssues: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devRisk',
    'Sec4Dev Risk Prioritization Results',
    vscode.ViewColumn.One,
    {}
  );

  const criticalIssues = prioritizedIssues.filter(i => i.riskAssessment.riskLevel === 'critical');
  const highIssues = prioritizedIssues.filter(i => i.riskAssessment.riskLevel === 'high');
  const mediumIssues = prioritizedIssues.filter(i => i.riskAssessment.riskLevel === 'medium');
  const lowIssues = prioritizedIssues.filter(i => i.riskAssessment.riskLevel === 'low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Risk Prioritization</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .issue { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
        .score { font-size: 24px; font-weight: bold; color: #1976d2; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🎯 Risk Prioritization Results</h1>
        <p>AI-powered risk assessment for ${prioritizedIssues.length} security issues</p>
      </div>
      
      <div class="stats">
        <p><strong>Critical:</strong> ${criticalIssues.length} | <strong>High:</strong> ${highIssues.length} | <strong>Medium:</strong> ${mediumIssues.length} | <strong>Low:</strong> ${lowIssues.length}</p>
      </div>
      
      ${prioritizedIssues.map(issue => `
        <div class="issue ${issue.riskAssessment.riskLevel}">
          <div class="score">Priority Score: ${issue.priorityScore.toFixed(1)}</div>
          <h3>${issue.originalIssue.type || 'Security Issue'} - Line ${issue.originalIssue.line}</h3>
          <p><strong>Risk Level:</strong> ${issue.riskAssessment.riskLevel.toUpperCase()}</p>
          <p><strong>Impact:</strong> ${issue.riskAssessment.impact}</p>
          <p><strong>Likelihood:</strong> ${issue.riskAssessment.likelihood}</p>
          <p><strong>Confidence:</strong> ${(issue.riskAssessment.confidence * 100).toFixed(1)}%</p>
          <p><strong>Recommended Action:</strong> ${issue.recommendedAction}</p>
          <p><strong>Time to Fix:</strong> ${issue.timeToFix}</p>
          <p><strong>Effort:</strong> ${issue.effort}</p>
          <p><strong>Explanation:</strong> ${issue.riskAssessment.explanation}</p>
          <p><strong>Business Impact:</strong> ${issue.riskAssessment.businessImpact}</p>
          <p><strong>Technical Impact:</strong> ${issue.riskAssessment.technicalImpact}</p>
          <p><strong>Remediation:</strong> ${issue.riskAssessment.remediation}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

function showSecurityTraining(lessons: any[]) {
  const panel = vscode.window.createWebviewPanel(
    'sec4devTraining',
    'Sec4Dev Security Training',
    vscode.ViewColumn.One,
    {}
  );

  const beginnerLessons = lessons.filter(l => l.difficulty === 'beginner');
  const intermediateLessons = lessons.filter(l => l.difficulty === 'intermediate');
  const advancedLessons = lessons.filter(l => l.difficulty === 'advanced');

  panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Security Training</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .lesson { background: #fff; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; }
        .beginner { border-left: 4px solid #388e3c; }
        .intermediate { border-left: 4px solid #fbc02d; }
        .advanced { border-left: 4px solid #d32f2f; }
        .category { font-weight: bold; color: #1976d2; }
        .difficulty { font-weight: bold; }
        .beginner .difficulty { color: #388e3c; }
        .intermediate .difficulty { color: #fbc02d; }
        .advanced .difficulty { color: #d32f2f; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🎓 Security Training Modules</h1>
        <p>Comprehensive security education for developers</p>
      </div>
      
      <h2>Beginner Level (${beginnerLessons.length} lessons)</h2>
      ${beginnerLessons.map(lesson => `
        <div class="lesson beginner">
          <h3>${lesson.title}</h3>
          <p class="category">Category: ${lesson.category.replace(/_/g, ' ')}</p>
          <p class="difficulty">Difficulty: ${lesson.difficulty}</p>
          <p>${lesson.description}</p>
        </div>
      `).join('')}
      
      <h2>Intermediate Level (${intermediateLessons.length} lessons)</h2>
      ${intermediateLessons.map(lesson => `
        <div class="lesson intermediate">
          <h3>${lesson.title}</h3>
          <p class="category">Category: ${lesson.category.replace(/_/g, ' ')}</p>
          <p class="difficulty">Difficulty: ${lesson.difficulty}</p>
          <p>${lesson.description}</p>
        </div>
      `).join('')}
      
      <h2>Advanced Level (${advancedLessons.length} lessons)</h2>
      ${advancedLessons.map(lesson => `
        <div class="lesson advanced">
          <h3>${lesson.title}</h3>
          <p class="category">Category: ${lesson.category.replace(/_/g, ' ')}</p>
          <p class="difficulty">Difficulty: ${lesson.difficulty}</p>
          <p>${lesson.description}</p>
        </div>
      `).join('')}
    </body>
    </html>
  `;
}

export function deactivate() {} 