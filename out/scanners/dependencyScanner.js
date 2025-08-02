"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DependencyScanner = void 0;
const vscode = require("vscode");
const fs = require("fs-extra");
const path = require("path");
const axios_1 = require("axios");
class DependencyScanner {
    constructor() {
        this.npmAuditCache = new Map();
    }
    async scan() {
        const vulnerabilities = [];
        try {
            // Scan package.json files
            const packageFiles = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**');
            for (const file of packageFiles) {
                const fileVulnerabilities = await this.scanPackageFile(file.fsPath);
                vulnerabilities.push(...fileVulnerabilities);
            }
            // Scan other dependency files
            const otherFiles = await vscode.workspace.findFiles('**/{requirements.txt,Pipfile,poetry.lock,composer.json,Gemfile,go.mod}', '**/node_modules/**');
            for (const file of otherFiles) {
                const fileVulnerabilities = await this.scanOtherDependencyFile(file.fsPath);
                vulnerabilities.push(...fileVulnerabilities);
            }
        }
        catch (error) {
            console.error('Error scanning dependencies:', error);
        }
        return vulnerabilities;
    }
    async scanFile(filePath) {
        const ext = path.extname(filePath);
        switch (ext) {
            case '.json':
                if (path.basename(filePath) === 'package.json') {
                    return await this.scanPackageFile(filePath);
                }
                break;
            case '.txt':
                if (path.basename(filePath) === 'requirements.txt') {
                    return await this.scanPythonRequirements(filePath);
                }
                break;
            case '.lock':
                if (path.basename(filePath) === 'poetry.lock') {
                    return await this.scanPoetryLock(filePath);
                }
                break;
        }
        return [];
    }
    async scanPackageFile(filePath) {
        const vulnerabilities = [];
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const packageJson = JSON.parse(content);
            const dependencies = {
                ...packageJson.dependencies,
                ...packageJson.devDependencies,
                ...packageJson.peerDependencies
            };
            for (const [packageName, version] of Object.entries(dependencies)) {
                const vulns = await this.checkNpmVulnerability(packageName, version);
                vulnerabilities.push(...vulns);
            }
        }
        catch (error) {
            console.error(`Error scanning package file ${filePath}:`, error);
        }
        return vulnerabilities;
    }
    async scanPythonRequirements(filePath) {
        const vulnerabilities = [];
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            for (const line of lines) {
                const match = line.match(/^([a-zA-Z0-9_-]+)==([0-9.]+)/);
                if (match) {
                    const [, packageName, version] = match;
                    const vulns = await this.checkPythonVulnerability(packageName, version);
                    vulnerabilities.push(...vulns);
                }
            }
        }
        catch (error) {
            console.error(`Error scanning Python requirements ${filePath}:`, error);
        }
        return vulnerabilities;
    }
    async scanPoetryLock(filePath) {
        const vulnerabilities = [];
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.startsWith('name = ')) {
                    const packageName = line.match(/name = "([^"]+)"/)?.[1];
                    const versionLine = lines[i + 1];
                    const version = versionLine.match(/version = "([^"]+)"/)?.[1];
                    if (packageName && version) {
                        const vulns = await this.checkPythonVulnerability(packageName, version);
                        vulnerabilities.push(...vulns);
                    }
                }
            }
        }
        catch (error) {
            console.error(`Error scanning Poetry lock ${filePath}:`, error);
        }
        return vulnerabilities;
    }
    async scanOtherDependencyFile(filePath) {
        const vulnerabilities = [];
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const fileName = path.basename(filePath);
            if (fileName === 'composer.json') {
                const composerJson = JSON.parse(content);
                const dependencies = {
                    ...composerJson.require,
                    ...composerJson['require-dev']
                };
                for (const [packageName, version] of Object.entries(dependencies)) {
                    const vulns = await this.checkPhpVulnerability(packageName, version);
                    vulnerabilities.push(...vulns);
                }
            }
            else if (fileName === 'Gemfile') {
                const lines = content.split('\n');
                for (const line of lines) {
                    const match = line.match(/gem ['"]([^'"]+)['"], ['"]([^'"]+)['"]/);
                    if (match) {
                        const [, packageName, version] = match;
                        const vulns = await this.checkRubyVulnerability(packageName, version);
                        vulnerabilities.push(...vulns);
                    }
                }
            }
            else if (fileName === 'go.mod') {
                const lines = content.split('\n');
                for (const line of lines) {
                    const match = line.match(/require ([^ ]+) ([^ ]+)/);
                    if (match) {
                        const [, packageName, version] = match;
                        const vulns = await this.checkGoVulnerability(packageName, version);
                        vulnerabilities.push(...vulns);
                    }
                }
            }
        }
        catch (error) {
            console.error(`Error scanning dependency file ${filePath}:`, error);
        }
        return vulnerabilities;
    }
    async checkNpmVulnerability(packageName, version) {
        const cacheKey = `npm:${packageName}:${version}`;
        if (this.npmAuditCache.has(cacheKey)) {
            return this.npmAuditCache.get(cacheKey);
        }
        try {
            // Simulate npm audit check (in real implementation, you'd call npm audit)
            const response = await axios_1.default.get(`https://registry.npmjs.org/${packageName}`);
            const vulnerabilities = [];
            // Simulate vulnerability check
            if (this.isVulnerableVersion(version)) {
                vulnerabilities.push({
                    package: packageName,
                    version,
                    severity: 'high',
                    description: `Known vulnerability in ${packageName} version ${version}`,
                    cve: 'CVE-2023-XXXX',
                    fixVersion: this.getNextVersion(version)
                });
            }
            this.npmAuditCache.set(cacheKey, vulnerabilities);
            return vulnerabilities;
        }
        catch (error) {
            console.error(`Error checking npm vulnerability for ${packageName}:`, error);
            return [];
        }
    }
    async checkPythonVulnerability(packageName, version) {
        try {
            // Simulate PyPI vulnerability check
            const vulnerabilities = [];
            if (this.isVulnerableVersion(version)) {
                vulnerabilities.push({
                    package: packageName,
                    version,
                    severity: 'medium',
                    description: `Potential vulnerability in ${packageName} version ${version}`,
                    fixVersion: this.getNextVersion(version)
                });
            }
            return vulnerabilities;
        }
        catch (error) {
            console.error(`Error checking Python vulnerability for ${packageName}:`, error);
            return [];
        }
    }
    async checkPhpVulnerability(packageName, version) {
        try {
            // Simulate Composer vulnerability check
            const vulnerabilities = [];
            if (this.isVulnerableVersion(version)) {
                vulnerabilities.push({
                    package: packageName,
                    version,
                    severity: 'low',
                    description: `Potential issue in ${packageName} version ${version}`,
                    fixVersion: this.getNextVersion(version)
                });
            }
            return vulnerabilities;
        }
        catch (error) {
            console.error(`Error checking PHP vulnerability for ${packageName}:`, error);
            return [];
        }
    }
    async checkRubyVulnerability(packageName, version) {
        try {
            // Simulate Ruby vulnerability check
            const vulnerabilities = [];
            if (this.isVulnerableVersion(version)) {
                vulnerabilities.push({
                    package: packageName,
                    version,
                    severity: 'medium',
                    description: `Potential vulnerability in ${packageName} version ${version}`,
                    fixVersion: this.getNextVersion(version)
                });
            }
            return vulnerabilities;
        }
        catch (error) {
            console.error(`Error checking Ruby vulnerability for ${packageName}:`, error);
            return [];
        }
    }
    async checkGoVulnerability(packageName, version) {
        try {
            // Simulate Go vulnerability check
            const vulnerabilities = [];
            if (this.isVulnerableVersion(version)) {
                vulnerabilities.push({
                    package: packageName,
                    version,
                    severity: 'high',
                    description: `Known vulnerability in ${packageName} version ${version}`,
                    fixVersion: this.getNextVersion(version)
                });
            }
            return vulnerabilities;
        }
        catch (error) {
            console.error(`Error checking Go vulnerability for ${packageName}:`, error);
            return [];
        }
    }
    isVulnerableVersion(version) {
        // Simulate vulnerability detection logic
        const vulnerableVersions = ['1.0.0', '2.0.0', '3.0.0'];
        return vulnerableVersions.includes(version) || Math.random() < 0.1; // 10% chance for demo
    }
    getNextVersion(version) {
        const parts = version.split('.');
        parts[parts.length - 1] = (parseInt(parts[parts.length - 1]) + 1).toString();
        return parts.join('.');
    }
}
exports.DependencyScanner = DependencyScanner;
//# sourceMappingURL=dependencyScanner.js.map