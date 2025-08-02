# Sec4Dev - Security for Developers Usage Guide

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Build the Extension
```bash
npm run compile
```

### 3. Run in Debug Mode
- Open the project in VS Code
- Press `F5` to launch a new VS Code window with the extension loaded
- Open the `test-examples.js` file to see the extension in action

## How to Use

### Command Palette Commands

1. **Scan Current Document**
   - Open any JavaScript/TypeScript file
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Sec4Dev: Scan Document for Security Issues"
   - Press Enter

2. **Scan Entire Workspace**
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Sec4Dev: Scan Workspace for Security Issues"
   - Press Enter

### Real-time Security Monitoring

The extension automatically scans your code as you type and shows warnings for:
- `eval()` function usage and dynamic code execution
- High-risk security patterns and vulnerabilities
- Suspicious code obfuscation and encoding
- Potential malware patterns

### Configuration

You can customize the extension behavior in VS Code settings:

1. Open Settings (`Ctrl+,` or `Cmd+,`)
2. Search for "Sec4Dev"
3. Configure:
   - `Enable Real-time Scanning`: Turn on/off live security monitoring
   - `Show Warnings`: Enable/disable security warnings

## Testing the Extension

1. Open the `test-examples.js` file in the debug VS Code window
2. Run the "Scan Document" command
3. You should see:
   - 4 HIGH RISK patterns (eval, Function, setTimeout, setInterval)
   - 6 MEDIUM RISK patterns (XOR, base64, encryption)
   - 3 LOW RISK patterns (unescape, decodeURIComponent, String.fromCharCode)

## Security Features

### High Risk Detection (🚨) - Critical Vulnerabilities
- Direct `eval()` calls - Immediate code execution
- `Function()` constructor with strings - Dynamic code creation
- `setTimeout()` with string code - Delayed execution
- `setInterval()` with string code - Repeated execution
- Process execution (`exec`, `spawn`) - System command execution

### Medium Risk Detection (⚠️) - Potential Threats
- XOR operations for obfuscation - Common malware technique
- Base64 encoding/decoding - Data hiding and payload encoding
- Encryption/decryption functions - Potential malicious encoding
- Buffer operations - Binary data manipulation

### Low Risk Detection (ℹ️) - Suspicious Patterns
- Code obfuscation techniques - Potential hiding of malicious code
- Character encoding operations - Suspicious data transformation
- URI decoding functions - Potential data exfiltration

## Extension Output

The extension provides:
- **Webview Panels**: Detailed security scan results with code snippets
- **Status Bar**: Quick summary of detected vulnerabilities
- **Notifications**: Real-time security warnings and alerts
- **Line Highlighting**: Shows exact line numbers of suspicious code
- **Risk Categorization**: Color-coded severity levels for easy identification

## Troubleshooting

### Extension Not Working?
1. Check the Output panel (`View > Output`) and select "Sec4Dev" from the dropdown
2. Look for any error messages
3. Make sure the extension is activated (check the Extensions panel)

### No Results Found?
1. Ensure you're scanning a supported file type (`.js`, `.ts`, `.jsx`, `.tsx`, `.py`, `.php`)
2. Check if the file contains any of the security patterns the extension looks for
3. Try the test file (`test-examples.js`) to verify the extension is working

### Performance Issues?
1. Disable real-time scanning in settings
2. Use workspace scanning instead of document scanning for large projects
3. Exclude `node_modules` and other large directories

## Development

### Adding New Security Patterns
To add new security patterns, edit `src/extension.ts` and add new regex patterns to the appropriate arrays:
- `evalPatterns` for eval-like functions and dynamic code execution
- `xorPatterns` for XOR operations and obfuscation
- `base64Patterns` for base64 operations and data hiding
- `obfuscatedPatterns` for code obfuscation techniques
- `dynamicCodePatterns` for dynamic code execution and process calls

### Customizing Severity Levels
Modify the `severity` field in the pattern detection logic to change risk levels:
- `'high'`: Critical security vulnerabilities
- `'medium'`: Potential security threats
- `'low'`: Suspicious patterns requiring review

## Security Best Practices

### For Developers
1. **Avoid eval()**: Never use eval() in production code
2. **Validate Input**: Always sanitize user input
3. **Use CSP**: Implement Content Security Policy
4. **Regular Scanning**: Use Sec4Dev for continuous security monitoring
5. **Code Review**: Regularly review code for security issues

### For Teams
1. **Automated Scanning**: Integrate Sec4Dev into CI/CD pipelines
2. **Security Training**: Educate team on secure coding practices
3. **Incident Response**: Have procedures for handling security alerts
4. **Regular Updates**: Keep tools and dependencies updated

## Support

For issues or feature requests, please check the README.md file or create an issue in the repository.

**Contact:**
- LinkedIn: linkedin.com/in/melihaybar/
- GitHub: github.com/notrealtrick