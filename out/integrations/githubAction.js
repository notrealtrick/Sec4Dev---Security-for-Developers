"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitHubAction = void 0;
const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
class GitHubAction {
    async generateAction() {
        return `name: Sec4Dev Security Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        
    - name: Install Sec4Dev
      run: npm install -g sec4dev-cli
      
    - name: Run security scan
      run: sec4dev scan --format json --output sec4dev-results.json
      
    - name: Comment on PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          
          if (fs.existsSync('sec4dev-results.json')) {
            const results = JSON.parse(fs.readFileSync('sec4dev-results.json', 'utf8'));
            
            let commentBody = '🔒 **Sec4Dev Security Scan Results**\\n\\n';
            commentBody += \`📊 **Summary:**\\n\`;
            commentBody += \`- Files Scanned: \${results.filesScanned}\\n\`;
            commentBody += \`- Issues Found: \${results.issuesFound}\\n\`;
            commentBody += \`- Security Score: \${results.securityScore}/100\\n\\n\`;
            
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: commentBody
            });
          }
          
    - name: Fail on critical issues
      if: failure()
      run: |
        echo "🚨 Security issues detected!"
        exit 1`;
    }
    async createActionFile() {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceRoot) {
            throw new Error('No workspace found');
        }
        const actionDir = path.join(workspaceRoot.uri.fsPath, '.github', 'workflows');
        const actionFile = path.join(actionDir, 'sec4dev-security.yml');
        try {
            // Create directories if they don't exist
            await fs.promises.mkdir(actionDir, { recursive: true });
            // Generate action content
            const actionContent = await this.generateAction();
            // Write action file
            await fs.promises.writeFile(actionFile, actionContent);
            vscode.window.showInformationMessage(`GitHub Action created at ${actionFile}`);
        }
        catch (error) {
            console.error('Error creating GitHub Action:', error);
            vscode.window.showErrorMessage(`Failed to create GitHub Action: ${error}`);
        }
    }
    async generatePRComment(scanResult) {
        let comment = '🔒 **Sec4Dev Security Scan Results**\n\n';
        comment += `📊 **Summary:**\n`;
        comment += `- Files Scanned: ${scanResult.filesScanned || 0}\n`;
        comment += `- Issues Found: ${scanResult.issuesFound || 0}\n`;
        comment += `- Security Score: ${scanResult.securityScore || 100}/100\n\n`;
        if (scanResult.summary) {
            comment += `📈 **Breakdown:**\n`;
            comment += `- Eval Usage: ${scanResult.summary.evalCount || 0}\n`;
            comment += `- Secrets: ${scanResult.summary.secretsCount || 0}\n`;
            comment += `- Vulnerabilities: ${scanResult.summary.vulnerabilitiesCount || 0}\n`;
            comment += `- OWASP Issues: ${scanResult.summary.owaspIssuesCount || 0}\n\n`;
        }
        if (scanResult.details && scanResult.details.length > 0) {
            comment += `📁 **Files with Issues:**\n`;
            for (const detail of scanResult.details.slice(0, 5)) {
                if (detail.issues && detail.issues.length > 0) {
                    comment += `- ${detail.file} (Score: ${detail.score}/100)\n`;
                    for (const issue of detail.issues.slice(0, 2)) {
                        comment += `  - ${issue}\n`;
                    }
                    if (detail.issues.length > 2) {
                        comment += `  - ... and ${detail.issues.length - 2} more issues\n`;
                    }
                }
            }
            comment += `\n`;
        }
        // Add recommendations
        comment += `💡 **Recommendations:**\n`;
        const summary = scanResult.summary || {};
        if (summary.evalCount > 0) {
            comment += `- Replace ${summary.evalCount} eval() usage with safer alternatives\n`;
        }
        if (summary.secretsCount > 0) {
            comment += `- Move ${summary.secretsCount} hardcoded secrets to environment variables\n`;
        }
        if (summary.vulnerabilitiesCount > 0) {
            comment += `- Review ${summary.vulnerabilitiesCount} potential vulnerabilities\n`;
        }
        if (summary.owaspIssuesCount > 0) {
            comment += `- Address ${summary.owaspIssuesCount} OWASP Top 10 issues\n`;
        }
        const score = scanResult.securityScore || 100;
        if (score < 60) {
            comment += `\n🚨 **Critical:** Immediate security review required\n`;
        }
        else if (score < 80) {
            comment += `\n⚠️ **Warning:** Security improvements needed\n`;
        }
        else {
            comment += `\n✅ **Good:** Security practices are being followed\n`;
        }
        return comment;
    }
    async generateAnnotations(scanResult) {
        const annotations = [];
        if (scanResult.details) {
            for (const detail of scanResult.details) {
                if (detail.issues) {
                    for (const issue of detail.issues) {
                        // Parse line number from issue message
                        const lineMatch = issue.match(/Line (\d+):/);
                        if (lineMatch) {
                            const lineNumber = parseInt(lineMatch[1]);
                            let level = 'notice';
                            if (issue.includes('eval()') || issue.includes('Secret')) {
                                level = 'failure';
                            }
                            else if (issue.includes('vulnerability') || issue.includes('XSS')) {
                                level = 'warning';
                            }
                            annotations.push({
                                path: detail.file,
                                start_line: lineNumber,
                                end_line: lineNumber,
                                annotation_level: level,
                                message: issue,
                                title: 'Sec4Dev Security Issue'
                            });
                        }
                    }
                }
            }
        }
        return annotations;
    }
}
exports.GitHubAction = GitHubAction;
//# sourceMappingURL=githubAction.js.map