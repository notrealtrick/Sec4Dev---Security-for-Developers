import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface TerminalCommand {
  type: 'base64_encoded' | 'powershell_encoded' | 'reverse_shell' | 'file_download' | 'privilege_escalation' | 'network_scan' | 'data_exfiltration' | 'obfuscated_command';
  line: number;
  code: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  suggestion: string;
  decodedCommand?: string;
}

export class TerminalScanner {
  private terminalPatterns = {
    // Base64 encoded commands
    base64_encoded: [
      /echo\s+["']([A-Za-z0-9+/]{20,}={0,2})["']\s*\|\s*base64\s*-d\s*\|\s*bash/gi,
      /echo\s+`([A-Za-z0-9+/]{20,}={0,2})`\s*\|\s*base64\s*-d\s*\|\s*bash/gi,
      /base64\s*-d\s*<<<["']([A-Za-z0-9+/]{20,}={0,2})["']\s*\|\s*bash/gi,
      /printf\s+["']([A-Za-z0-9+/]{20,}={0,2})["']\s*\|\s*base64\s*-d\s*\|\s*bash/gi
    ],

    // PowerShell encoded commands
    powershell_encoded: [
      /powershell\s+-enc\s+["']([A-Za-z0-9+/]{20,}={0,2})["']/gi,
      /powershell\s+-encodedcommand\s+["']([A-Za-z0-9+/]{20,}={0,2})["']/gi,
      /powershell\s+-e\s+["']([A-Za-z0-9+/]{20,}={0,2})["']/gi
    ],

    // Reverse shell connections
    reverse_shell: [
      /bash\s+-i\s*>&\s*\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,5}\s*0>&1/gi,
      /nc\s+-e\s+\/bin\/bash\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9]{1,5}/gi,
      /netcat\s+-e\s+\/bin\/bash\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9]{1,5}/gi,
      /python\s+-c\s+["']import\s+socket,subprocess,os;s=socket\.socket\(socket\.AF_INET,socket\.SOCK_STREAM\);s\.connect\(\(["'][^"']+["'],\d+\)\);os\.dup2\(s\.fileno\(\),0\);os\.dup2\(s\.fileno\(\),1\);os\.dup2\(s\.fileno\(\),2\);subprocess\.call\(\[["']\/bin\/sh["'],\["\]\)["']/gi
    ],

    // File download and execution
    file_download: [
      /(?:wget|curl)\s+[^|]+\s*\|\s*bash/gi,
      /(?:wget|curl)\s+[^|]+\s*\|\s*sh/gi,
      /(?:wget|curl)\s+[^|]+\s*\|\s*\/bin\/bash/gi,
      /(?:wget|curl)\s+-s\s+[^|]+\s*\|\s*bash/gi,
      /(?:wget|curl)\s+--silent\s+[^|]+\s*\|\s*bash/gi
    ],

    // Privilege escalation attempts
    privilege_escalation: [
      /sudo\s+[^|]+\s*\|\s*bash/gi,
      /su\s+[^|]+\s*\|\s*bash/gi,
      /sudo\s+[^|]+\s*\|\s*sh/gi,
      /su\s+[^|]+\s*\|\s*sh/gi
    ],

    // Network scanning commands
    network_scan: [
      /nmap\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/gi,
      /netcat\s+-z\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/gi,
      /nc\s+-z\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/gi,
      /masscan\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/gi
    ],

    // Data exfiltration patterns
    data_exfiltration: [
      /tar\s+[^|]+\s*\|\s*(?:nc|netcat|curl|wget)/gi,
      /zip\s+[^|]+\s*\|\s*(?:nc|netcat|curl|wget)/gi,
      /gzip\s+[^|]+\s*\|\s*(?:nc|netcat|curl|wget)/gi,
      /dd\s+[^|]+\s*\|\s*(?:nc|netcat|curl|wget)/gi
    ],

    // Obfuscated commands (XOR, hex, URL encoding)
    obfuscated_command: [
      /echo\s+["'][0-9a-fA-F]{20,}["']\s*\|\s*xxd\s*-r\s*\|\s*bash/gi,
      /printf\s+["'][0-9a-fA-F]{20,}["']\s*\|\s*xxd\s*-r\s*\|\s*bash/gi,
      /echo\s+["'][%0-9a-fA-F]{20,}["']\s*\|\s*perl\s+-e\s+["']print\s+pack\s*\(["']H\*["'],\s*<STDIN>\)["']\s*\|\s*bash/gi,
      /echo\s+["'][%0-9a-fA-F]{20,}["']\s*\|\s*python\s+-c\s+["']import\s+urllib;print\s+urllib\.unquote_plus\(raw_input\(\)\)["']\s*\|\s*bash/gi
    ]
  };

  async scan(): Promise<TerminalCommand[]> {
    const commands: TerminalCommand[] = [];
    
    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{sh,bash,ps1,bat,cmd,js,ts,py,php,rb,pl,go,rs,java,cpp,c,cs}',
        '**/node_modules/**'
      );

      for (const file of files) {
        const fileCommands = await this.scanFile(file.fsPath);
        commands.push(...fileCommands);
      }

    } catch (error) {
      console.error('Error scanning terminal commands:', error);
    }

    return commands;
  }

  async scanFile(filePath: string): Promise<TerminalCommand[]> {
    const commands: TerminalCommand[] = [];
    
    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;

        // Check each command type
        for (const [type, patterns] of Object.entries(this.terminalPatterns)) {
          for (const pattern of patterns) {
            const matches = line.matchAll(pattern);
            
            for (const match of matches) {
              const encodedValue = match[1] || match[0];
              const severity = this.getCommandSeverity(type as any, encodedValue);
              const decodedCommand = this.tryDecodeCommand(type as any, encodedValue);
              
              commands.push({
                type: type as any,
                line: lineNumber,
                code: line.trim(),
                severity,
                description: this.getCommandDescription(type as any, encodedValue),
                suggestion: this.getCommandSuggestion(type as any),
                decodedCommand
              });
            }
          }
        }

        // Check for suspicious command combinations
        const suspiciousCommands = this.checkSuspiciousCombinations(line, lineNumber);
        commands.push(...suspiciousCommands);
      }

    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
    }

    return commands;
  }

  private checkSuspiciousCombinations(line: string, lineNumber: number): TerminalCommand[] {
    const commands: TerminalCommand[] = [];
    
    // Check for pipe to bash/sh with suspicious patterns
    const pipeToShellPatterns = [
      /[^|]+\|\s*bash/gi,
      /[^|]+\|\s*sh/gi,
      /[^|]+\|\s*\/bin\/bash/gi,
      /[^|]+\|\s*\/bin\/sh/gi
    ];

    for (const pattern of pipeToShellPatterns) {
      if (pattern.test(line) && this.isSuspiciousPipe(line)) {
        commands.push({
          type: 'obfuscated_command',
          line: lineNumber,
          code: line.trim(),
          severity: 'medium',
          description: 'Suspicious command piped to shell interpreter',
          suggestion: 'Review the command being piped to shell. Consider using explicit command validation.'
        });
      }
    }

    return commands;
  }

  private isSuspiciousPipe(line: string): boolean {
    const suspiciousKeywords = [
      'curl', 'wget', 'nc', 'netcat', 'nmap', 'masscan',
      'base64', 'xxd', 'hex', 'url', 'encode', 'decode',
      'eval', 'exec', 'system', 'popen'
    ];

    return suspiciousKeywords.some(keyword => 
      line.toLowerCase().includes(keyword.toLowerCase())
    );
  }

  private tryDecodeCommand(type: TerminalCommand['type'], encodedValue: string): string | undefined {
    try {
      switch (type) {
        case 'base64_encoded':
          return Buffer.from(encodedValue, 'base64').toString('utf8');
        case 'powershell_encoded':
          return Buffer.from(encodedValue, 'base64').toString('utf8');
        case 'obfuscated_command':
          if (encodedValue.match(/^[0-9a-fA-F]+$/)) {
            return Buffer.from(encodedValue, 'hex').toString('utf8');
          }
          break;
      }
    } catch (error) {
      // Decoding failed, return undefined
    }
    return undefined;
  }

  private getCommandSeverity(type: TerminalCommand['type'], value: string): 'high' | 'medium' | 'low' {
    switch (type) {
      case 'base64_encoded':
      case 'powershell_encoded':
      case 'reverse_shell':
      case 'file_download':
        return 'high';
      case 'privilege_escalation':
      case 'network_scan':
      case 'data_exfiltration':
        return 'medium';
      case 'obfuscated_command':
        return 'medium';
      default:
        return 'low';
    }
  }

  private getCommandDescription(type: TerminalCommand['type'], value: string): string {
    switch (type) {
      case 'base64_encoded':
        return 'Base64 encoded command detected. This is a common technique to obfuscate malicious commands.';
      case 'powershell_encoded':
        return 'PowerShell encoded command detected. This can be used to execute obfuscated PowerShell scripts.';
      case 'reverse_shell':
        return 'Reverse shell connection detected. This creates a backdoor connection to a remote attacker.';
      case 'file_download':
        return 'File download and execution detected. This can download and run malicious payloads.';
      case 'privilege_escalation':
        return 'Privilege escalation attempt detected. This tries to gain elevated permissions.';
      case 'network_scan':
        return 'Network scanning command detected. This can be used for reconnaissance.';
      case 'data_exfiltration':
        return 'Data exfiltration pattern detected. This can be used to steal sensitive data.';
      case 'obfuscated_command':
        return 'Obfuscated command detected. This uses encoding to hide malicious intent.';
      default:
        return 'Suspicious terminal command detected.';
    }
  }

  private getCommandSuggestion(type: TerminalCommand['type']): string {
    switch (type) {
      case 'base64_encoded':
      case 'powershell_encoded':
      case 'obfuscated_command':
        return 'Review the decoded command. Consider using explicit command validation and avoid executing encoded commands.';
      case 'reverse_shell':
        return 'Remove reverse shell connections. Use secure remote access methods instead.';
      case 'file_download':
        return 'Use package managers and trusted sources for software installation. Validate downloaded files.';
      case 'privilege_escalation':
        return 'Review privilege escalation needs. Use proper authentication and authorization.';
      case 'network_scan':
        return 'Ensure network scanning is authorized and follows security policies.';
      case 'data_exfiltration':
        return 'Review data handling practices. Use secure data transfer methods.';
      default:
        return 'Review the command for security implications and consider alternatives.';
    }
  }
} 