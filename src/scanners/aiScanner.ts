import * as vscode from 'vscode';

export interface AIAnalysis {
  intent: 'malicious' | 'suspicious' | 'benign';
  confidence: number;
  explanation: string;
  riskLevel: 'high' | 'medium' | 'low';
}

export class AIScanner {
  private maliciousPatterns = [
    // Code execution patterns
    /eval\s*\(/gi,
    /Function\s*\(\s*["'][^"']*["']/gi,
    /setTimeout\s*\(\s*["'][^"']*["']/gi,
    /setInterval\s*\(\s*["']*["']/gi,
    
    // Process execution
    /exec\s*\(/gi,
    /spawn\s*\(/gi,
    /child_process/gi,
    
    // Network requests
    /fetch\s*\(\s*[^)]*\+/gi,
    /axios\s*\(\s*[^)]*\+/gi,
    /request\s*\(\s*[^)]*\+/gi,
    
    // File operations
    /readFile\s*\(\s*[^)]*\+/gi,
    /writeFile\s*\(\s*[^)]*\+/gi,
    /unlink\s*\(\s*[^)]*\+/gi,
    
    // Database operations
    /query\s*\(\s*[^)]*\+/gi,
    /execute\s*\(\s*[^)]*\+/gi,
    
    // Shell commands
    /shell\s*\(/gi,
    /cmd\s*\(/gi,
    /system\s*\(/gi
  ];

  private suspiciousPatterns = [
    // Encoding/decoding
    /base64/gi,
    /atob\s*\(/gi,
    /btoa\s*\(/gi,
    /decodeURIComponent\s*\(/gi,
    /unescape\s*\(/gi,
    
    // Character manipulation
    /String\.fromCharCode/gi,
    /charCodeAt/gi,
    /charAt/gi,
    
    // XOR operations
    /\^[\s\S]*\b/gi,
    /xor/gi,
    
    // Dynamic code
    /new\s+Function/gi,
    /constructor/gi,
    
    // Network patterns
    /http:\/\//gi,
    /localhost/gi,
    /127\.0\.0\.1/gi
  ];

  async analyze(code: string): Promise<AIAnalysis> {
    const maliciousScore = this.calculateMaliciousScore(code);
    const suspiciousScore = this.calculateSuspiciousScore(code);
    const totalScore = maliciousScore + suspiciousScore;

    let intent: 'malicious' | 'suspicious' | 'benign';
    let confidence: number;
    let riskLevel: 'high' | 'medium' | 'low';

    if (maliciousScore > 0.7) {
      intent = 'malicious';
      confidence = Math.min(0.9, maliciousScore);
      riskLevel = 'high';
    } else if (totalScore > 0.5) {
      intent = 'suspicious';
      confidence = Math.min(0.8, totalScore);
      riskLevel = 'medium';
    } else {
      intent = 'benign';
      confidence = Math.max(0.6, 1 - totalScore);
      riskLevel = 'low';
    }

    const explanation = this.generateExplanation(code, maliciousScore, suspiciousScore);

    return {
      intent,
      confidence,
      explanation,
      riskLevel
    };
  }

  private calculateMaliciousScore(code: string): number {
    let score = 0;
    let totalMatches = 0;

    for (const pattern of this.maliciousPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        totalMatches += matches.length;
        score += matches.length * 0.3; // Each malicious pattern adds 30% to score
      }
    }

    // Normalize score
    return Math.min(1.0, score);
  }

  private calculateSuspiciousScore(code: string): number {
    let score = 0;
    let totalMatches = 0;

    for (const pattern of this.suspiciousPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        totalMatches += matches.length;
        score += matches.length * 0.15; // Each suspicious pattern adds 15% to score
      }
    }

    // Normalize score
    return Math.min(1.0, score);
  }

  private generateExplanation(code: string, maliciousScore: number, suspiciousScore: number): string {
    const explanations: string[] = [];

    if (maliciousScore > 0.7) {
      explanations.push('High risk of malicious code execution detected');
    } else if (maliciousScore > 0.3) {
      explanations.push('Potential malicious code patterns detected');
    }

    if (suspiciousScore > 0.5) {
      explanations.push('Multiple suspicious code patterns found');
    } else if (suspiciousScore > 0.2) {
      explanations.push('Some suspicious patterns detected');
    }

    // Add specific pattern explanations
    const specificPatterns = this.analyzeSpecificPatterns(code);
    if (specificPatterns.length > 0) {
      explanations.push(`Specific concerns: ${specificPatterns.join(', ')}`);
    }

    if (explanations.length === 0) {
      return 'Code appears to be safe with no obvious security concerns';
    }

    return explanations.join('. ');
  }

  private analyzeSpecificPatterns(code: string): string[] {
    const patterns: string[] = [];

    // Check for specific dangerous patterns
    if (code.includes('eval(')) {
      patterns.push('eval() usage');
    }
    if (code.includes('Function(')) {
      patterns.push('Function constructor');
    }
    if (code.includes('exec(')) {
      patterns.push('process execution');
    }
    if (code.includes('child_process')) {
      patterns.push('child process usage');
    }
    if (code.includes('innerHTML')) {
      patterns.push('innerHTML manipulation');
    }
    if (code.includes('document.write')) {
      patterns.push('document.write usage');
    }
    if (code.includes('base64')) {
      patterns.push('base64 encoding/decoding');
    }
    if (code.includes('localhost') || code.includes('127.0.0.1')) {
      patterns.push('localhost references');
    }
    if (code.includes('http://')) {
      patterns.push('insecure HTTP URLs');
    }

    return patterns;
  }

  // Advanced analysis methods
  async analyzeContext(filePath: string, code: string): Promise<AIAnalysis> {
    const baseAnalysis = await this.analyze(code);
    
    // Consider file context
    const contextScore = this.analyzeFileContext(filePath);
    const adjustedConfidence = Math.min(1.0, baseAnalysis.confidence + contextScore);

    return {
      ...baseAnalysis,
      confidence: adjustedConfidence,
      explanation: `${baseAnalysis.explanation}. File context analysis: ${this.getContextExplanation(contextScore)}`
    };
  }

  private analyzeFileContext(filePath: string): number {
    const fileName = filePath.toLowerCase();
    let contextScore = 0;

    // Suspicious file names
    if (fileName.includes('test') || fileName.includes('dev') || fileName.includes('debug')) {
      contextScore += 0.1;
    }

    // Configuration files
    if (fileName.includes('config') || fileName.includes('env') || fileName.includes('secret')) {
      contextScore += 0.2;
    }

    // Build or deployment files
    if (fileName.includes('build') || fileName.includes('deploy') || fileName.includes('script')) {
      contextScore += 0.15;
    }

    return contextScore;
  }

  private getContextExplanation(contextScore: number): string {
    if (contextScore > 0.3) {
      return 'File context suggests potential security concerns';
    } else if (contextScore > 0.1) {
      return 'File context shows some security considerations';
    } else {
      return 'File context appears normal';
    }
  }

  // Behavioral analysis
  async analyzeBehavior(code: string): Promise<AIAnalysis> {
    const behaviorPatterns = [
      // Network behavior
      { pattern: /fetch\s*\(/gi, weight: 0.2, description: 'Network requests' },
      { pattern: /axios\s*\(/gi, weight: 0.2, description: 'HTTP client usage' },
      
      // File system behavior
      { pattern: /readFile/gi, weight: 0.3, description: 'File reading' },
      { pattern: /writeFile/gi, weight: 0.4, description: 'File writing' },
      
      // Process behavior
      { pattern: /exec/gi, weight: 0.5, description: 'Process execution' },
      { pattern: /spawn/gi, weight: 0.5, description: 'Process spawning' },
      
      // Database behavior
      { pattern: /query/gi, weight: 0.3, description: 'Database queries' },
      { pattern: /execute/gi, weight: 0.3, description: 'Database execution' }
    ];

    let behaviorScore = 0;
    const behaviors: string[] = [];

    for (const { pattern, weight, description } of behaviorPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        behaviorScore += weight;
        behaviors.push(description);
      }
    }

    const intent = behaviorScore > 0.5 ? 'suspicious' : 'benign';
    const confidence = Math.min(0.9, behaviorScore);
    const riskLevel = behaviorScore > 0.7 ? 'high' : behaviorScore > 0.3 ? 'medium' : 'low';

    return {
      intent,
      confidence,
      explanation: `Behavioral analysis detected: ${behaviors.join(', ')}`,
      riskLevel
    };
  }
} 