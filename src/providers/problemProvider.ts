import * as vscode from 'vscode';

export class ProblemProvider implements vscode.TreeDataProvider<SecurityProblem> {
  private _onDidChangeTreeData: vscode.EventEmitter<SecurityProblem | undefined | null | void> = new vscode.EventEmitter<SecurityProblem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<SecurityProblem | undefined | null | void> = this._onDidChangeTreeData.event;

  private problems: SecurityProblem[] = [];

  constructor() {}

  getTreeItem(element: SecurityProblem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: SecurityProblem): Thenable<SecurityProblem[]> {
    if (!element) {
      return Promise.resolve(this.problems);
    }
    return Promise.resolve([]);
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  updateProblems(newProblems: SecurityProblem[]): void {
    this.problems = newProblems;
    this.refresh();
  }

  clearProblems(): void {
    this.problems = [];
    this.refresh();
  }
}

export class SecurityProblem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly severity: 'high' | 'medium' | 'low',
    public readonly description: string,
    public readonly filePath?: string,
    public readonly line?: number
  ) {
    super(label, vscode.TreeItemCollapsibleState.None);

    this.tooltip = description;
    this.description = severity.toUpperCase();

    // Set icon based on severity
    switch (severity) {
      case 'high':
        this.iconPath = new vscode.ThemeIcon('error');
        break;
      case 'medium':
        this.iconPath = new vscode.ThemeIcon('warning');
        break;
      case 'low':
        this.iconPath = new vscode.ThemeIcon('info');
        break;
    }

    // Add context value for commands
    this.contextValue = `securityProblem.${severity}`;

    // Add command to open file at specific line
    if (filePath && line) {
      this.command = {
        command: 'vscode.open',
        title: 'Open File',
        arguments: [
          vscode.Uri.file(filePath),
          {
            selection: new vscode.Range(line - 1, 0, line - 1, 100)
          }
        ]
      };
    }
  }
} 