import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface SecurityScore {
  score: number;
  level: 'excellent' | 'good' | 'poor';
  recommendations: string[];
  previousScore?: number;
  improvement?: number;
}

export class SecurityScoreCalculator {
  private readonly weights = {
    evalUsage: -20,
    suspiciousPatterns: -10,
    dependencyVulnerabilities: -15,
    secrets: -25,
    owaspIssues: -20,
    aiMalicious: -30,
    aiSuspicious: -10
  };

  async calculateScore(): Promise<SecurityScore> {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceRoot) {
      return this.getDefaultScore();
    }

    const score = await this.calculateWorkspaceScore(workspaceRoot.uri.fsPath);
    const level = this.getScoreLevel(score);
    const recommendations = this.getRecommendations(score);

    return {
      score,
      level,
      recommendations
    };
  }

  async calculateFileScore(result: any): Promise<number> {
    let score = 100;

    // Deduct points for each issue type
    if (result.evalCount > 0) {
      score += this.weights.evalUsage * result.evalCount;
    }

    if (result.suspiciousPatterns) {
      const highRisk = result.suspiciousPatterns.filter((p: any) => p.severity === 'high').length;
      const mediumRisk = result.suspiciousPatterns.filter((p: any) => p.severity === 'medium').length;
      const lowRisk = result.suspiciousPatterns.filter((p: any) => p.severity === 'low').length;

      score += this.weights.suspiciousPatterns * (highRisk * 3 + mediumRisk * 2 + lowRisk);
    }

    if (result.dependencyVulnerabilities) {
      const critical = result.dependencyVulnerabilities.filter((v: any) => v.severity === 'critical').length;
      const high = result.dependencyVulnerabilities.filter((v: any) => v.severity === 'high').length;
      const medium = result.dependencyVulnerabilities.filter((v: any) => v.severity === 'medium').length;

      score += this.weights.dependencyVulnerabilities * (critical * 4 + high * 3 + medium * 2);
    }

    if (result.secrets) {
      const highRisk = result.secrets.filter((s: any) => s.severity === 'high').length;
      const mediumRisk = result.secrets.filter((s: any) => s.severity === 'medium').length;

      score += this.weights.secrets * (highRisk * 3 + mediumRisk * 2);
    }

    if (result.owaspIssues) {
      const highRisk = result.owaspIssues.filter((o: any) => o.severity === 'high').length;
      const mediumRisk = result.owaspIssues.filter((o: any) => o.severity === 'medium').length;

      score += this.weights.owaspIssues * (highRisk * 3 + mediumRisk * 2);
    }

    if (result.aiAnalysis) {
      if (result.aiAnalysis.intent === 'malicious') {
        score += this.weights.aiMalicious;
      } else if (result.aiAnalysis.intent === 'suspicious') {
        score += this.weights.aiSuspicious;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  private async calculateWorkspaceScore(workspacePath: string): Promise<number> {
    let totalScore = 0;
    let fileCount = 0;

    try {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,php,json,yaml,yml}',
        '**/node_modules/**'
      );

      for (const file of files) {
        try {
          const document = await vscode.workspace.openTextDocument(file);
          const content = document.getText();
          
          // Simple scoring based on file content
          const fileScore = this.calculateFileContentScore(content);
          totalScore += fileScore;
          fileCount++;
        } catch (error) {
          console.error(`Error processing file ${file.fsPath}:`, error);
        }
      }

      return fileCount > 0 ? totalScore / fileCount : 100;
    } catch (error) {
      console.error('Error calculating workspace score:', error);
      return 100;
    }
  }

  private calculateFileContentScore(content: string): number {
    let score = 100;

    // Check for eval usage
    const evalMatches = content.match(/eval\s*\(/gi);
    if (evalMatches) {
      score -= this.weights.evalUsage * evalMatches.length;
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /Function\s*\(\s*["'][^"']*["']/gi,
      /setTimeout\s*\(\s*["'][^"']*["']/gi,
      /setInterval\s*\(\s*["'][^"']*["']/gi,
      /exec\s*\(/gi,
      /spawn\s*\(/gi,
      /child_process/gi
    ];

    for (const pattern of suspiciousPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        score += this.weights.suspiciousPatterns * matches.length;
      }
    }

    // Check for secrets
    const secretPatterns = [
      /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["'][^"']{20,}["']/gi,
      /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi,
      /(?:token|access_token|bearer_token)\s*[:=]\s*["'][^"']{20,}["']/gi
    ];

    for (const pattern of secretPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        score += this.weights.secrets * matches.length;
      }
    }

    // Check for OWASP issues
    const owaspPatterns = [
      /(?:sql|query)\s*[:=]\s*["'][^"']*["']/gi,
      /(?:innerHTML|outerHTML)\s*[:=]/gi,
      /(?:document\.write|document\.writeln)\s*\(/gi,
      /(?:localhost|127\.0\.0\.1)/gi,
      /http:\/\//gi
    ];

    for (const pattern of owaspPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        score += this.weights.owaspIssues * matches.length;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  private getScoreLevel(score: number): 'excellent' | 'good' | 'poor' {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    return 'poor';
  }

  private getRecommendations(score: number): string[] {
    const recommendations: string[] = [];

    if (score < 80) {
      recommendations.push('Review and fix security vulnerabilities');
    }
    if (score < 60) {
      recommendations.push('Implement comprehensive security measures');
      recommendations.push('Consider security training for the team');
    }
    if (score < 40) {
      recommendations.push('Critical security issues need immediate attention');
      recommendations.push('Consider external security audit');
    }

    return recommendations;
  }

  private getDefaultScore(): SecurityScore {
    return {
      score: 100,
      level: 'excellent',
      recommendations: ['No security issues detected']
    };
  }

  // Weekly progress tracking
  async getWeeklyProgress(): Promise<{ previousScore: number; improvement: number }> {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceRoot) {
      return { previousScore: 100, improvement: 0 };
    }

    const scoreFile = path.join(workspaceRoot.uri.fsPath, '.sec4dev-score.json');
    
    try {
      const currentScore = await this.calculateScore();
      
      if (await fs.promises.access(scoreFile).then(() => true).catch(() => false)) {
        const scoreData = JSON.parse(await fs.promises.readFile(scoreFile, 'utf8'));
        const previousScore = scoreData.score || 100;
        const improvement = currentScore.score - previousScore;

        // Update score file
        await fs.promises.writeFile(scoreFile, JSON.stringify({
          score: currentScore.score,
          timestamp: new Date().toISOString()
        }));

        return { previousScore, improvement };
      } else {
        // First time running
        await fs.promises.writeFile(scoreFile, JSON.stringify({
          score: currentScore.score,
          timestamp: new Date().toISOString()
        }));

        return { previousScore: currentScore.score, improvement: 0 };
      }
    } catch (error) {
      console.error('Error tracking weekly progress:', error);
      return { previousScore: 100, improvement: 0 };
    }
  }
} 