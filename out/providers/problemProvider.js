"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityProblem = exports.ProblemProvider = void 0;
const vscode = require("vscode");
class ProblemProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.problems = [];
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!element) {
            return Promise.resolve(this.problems);
        }
        return Promise.resolve([]);
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    updateProblems(newProblems) {
        this.problems = newProblems;
        this.refresh();
    }
    clearProblems() {
        this.problems = [];
        this.refresh();
    }
}
exports.ProblemProvider = ProblemProvider;
class SecurityProblem extends vscode.TreeItem {
    constructor(label, severity, description, filePath, line) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.label = label;
        this.severity = severity;
        this.description = description;
        this.filePath = filePath;
        this.line = line;
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
exports.SecurityProblem = SecurityProblem;
//# sourceMappingURL=problemProvider.js.map