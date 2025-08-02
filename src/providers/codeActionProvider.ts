import * as vscode from 'vscode';

export class CodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const codeActions: vscode.CodeAction[] = [];

    // Check for eval usage
    const evalAction = this.createEvalFix(document, range, context);
    if (evalAction) {
      codeActions.push(evalAction);
    }

    // Check for hardcoded secrets
    const secretAction = this.createSecretFix(document, range, context);
    if (secretAction) {
      codeActions.push(secretAction);
    }

    // Check for SQL injection
    const sqlAction = this.createSQLFix(document, range, context);
    if (sqlAction) {
      codeActions.push(sqlAction);
    }

    // Check for XSS
    const xssAction = this.createXSSFix(document, range, context);
    if (xssAction) {
      codeActions.push(xssAction);
    }

    return codeActions;
  }

  private createEvalFix(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction | undefined {
    const diagnostics = context.diagnostics.filter(d => 
      d.message.includes('eval') || d.message.includes('Eval')
    );

    if (diagnostics.length === 0) return undefined;

    const action = new vscode.CodeAction(
      'Replace eval() with safer alternative',
      vscode.CodeActionKind.QuickFix
    );

    action.diagnostics = diagnostics;
    action.edit = new vscode.WorkspaceEdit();

    // Get the line text
    const line = document.lineAt(range.start.line);
    const lineText = line.text;

    // Find eval usage and suggest alternatives
    const evalMatch = lineText.match(/eval\s*\(\s*([^)]+)\s*\)/);
    if (evalMatch) {
      const evalArg = evalMatch[1];
      
      // Suggest JSON.parse for JSON data
      if (evalArg.includes('{') && evalArg.includes('}')) {
        action.edit.replace(
          document.uri,
          range,
          `JSON.parse(${evalArg})`
        );
      } else {
        // Generic suggestion
        action.edit.replace(
          document.uri,
          range,
          `// TODO: Replace eval() with safer alternative\n// Original: eval(${evalArg})`
        );
      }
    }

    return action;
  }

  private createSecretFix(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction | undefined {
    const diagnostics = context.diagnostics.filter(d => 
      d.message.includes('Secret') || d.message.includes('password') || d.message.includes('API')
    );

    if (diagnostics.length === 0) return undefined;

    const action = new vscode.CodeAction(
      'Move secret to environment variable',
      vscode.CodeActionKind.QuickFix
    );

    action.diagnostics = diagnostics;
    action.edit = new vscode.WorkspaceEdit();

    const line = document.lineAt(range.start.line);
    const lineText = line.text;

    // Find secret patterns
    const secretPatterns = [
      { regex: /(api[_-]?key|apikey|api_key)\s*[:=]\s*["']([^"']+)["']/gi, envVar: 'API_KEY' },
      { regex: /(password|passwd|pwd)\s*[:=]\s*["']([^"']+)["']/gi, envVar: 'PASSWORD' },
      { regex: /(token|access_token|bearer_token)\s*[:=]\s*["']([^"']+)["']/gi, envVar: 'TOKEN' }
    ];

    for (const pattern of secretPatterns) {
      const match = lineText.match(pattern.regex);
      if (match) {
        action.edit.replace(
          document.uri,
          range,
          lineText.replace(match[0], `${match[1]} = process.env.${pattern.envVar}`)
        );
        break;
      }
    }

    return action;
  }

  private createSQLFix(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction | undefined {
    const diagnostics = context.diagnostics.filter(d => 
      d.message.includes('SQL') || d.message.includes('injection')
    );

    if (diagnostics.length === 0) return undefined;

    const action = new vscode.CodeAction(
      'Use parameterized query',
      vscode.CodeActionKind.QuickFix
    );

    action.diagnostics = diagnostics;
    action.edit = new vscode.WorkspaceEdit();

    const line = document.lineAt(range.start.line);
    const lineText = line.text;

    // Find SQL query with string concatenation
    const sqlMatch = lineText.match(/(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+WHERE\s+.*\s*\+/i);
    if (sqlMatch) {
      action.edit.replace(
        document.uri,
        range,
        `// TODO: Use parameterized query\n// Original: ${lineText}\n// Suggested: Use prepared statements or parameterized queries`
      );
    }

    return action;
  }

  private createXSSFix(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction | undefined {
    const diagnostics = context.diagnostics.filter(d => 
      d.message.includes('XSS') || d.message.includes('innerHTML') || d.message.includes('outerHTML')
    );

    if (diagnostics.length === 0) return undefined;

    const action = new vscode.CodeAction(
      'Sanitize user input',
      vscode.CodeActionKind.QuickFix
    );

    action.diagnostics = diagnostics;
    action.edit = new vscode.WorkspaceEdit();

    const line = document.lineAt(range.start.line);
    const lineText = line.text;

    // Find innerHTML/outerHTML usage
    const xssMatch = lineText.match(/(innerHTML|outerHTML)\s*[:=]\s*([^;]+)/i);
    if (xssMatch) {
      action.edit.replace(
        document.uri,
        range,
        `// TODO: Sanitize user input\n// Original: ${lineText}\n// Suggested: Use textContent or sanitize HTML input`
      );
    }

    return action;
  }
} 