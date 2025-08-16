import * as vscode from 'vscode';

export interface RiskAssessment {
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  impact: 'severe' | 'moderate' | 'minor';
  likelihood: 'very_likely' | 'likely' | 'unlikely' | 'very_unlikely';
  context: string;
  priority: number;
  explanation: string;
  remediation: string;
  businessImpact: string;
  technicalImpact: string;
}

export interface PrioritizedIssue {
  originalIssue: any;
  riskAssessment: RiskAssessment;
  priorityScore: number;
  recommendedAction: string;
  timeToFix: 'immediate' | 'high' | 'medium' | 'low';
  effort: 'high' | 'medium' | 'low';
}

export class RiskPrioritizationScanner {
  private riskFactors = {
    // Context-based risk factors
    production: 2.0,
    userInput: 1.8,
    authentication: 1.6,
    dataSensitive: 1.5,
    networkExposed: 1.4,
    thirdParty: 1.3,
    legacy: 1.2,
    development: 0.8,

    // Impact factors
    dataBreach: 2.0,
    systemCompromise: 1.8,
    serviceDisruption: 1.5,
    complianceViolation: 1.4,
    reputationDamage: 1.3,
    financialLoss: 1.2,

    // Likelihood factors
    publicExposure: 1.8,
    knownVulnerability: 1.6,
    activeExploitation: 1.5,
    weakControls: 1.4,
    complexity: 1.2
  };

  async prioritizeIssues(issues: any[], context: any = {}): Promise<PrioritizedIssue[]> {
    const prioritizedIssues: PrioritizedIssue[] = [];

    for (const issue of issues) {
      const riskAssessment = await this.assessRisk(issue, context);
      const priorityScore = this.calculatePriorityScore(riskAssessment);
      const recommendedAction = this.getRecommendedAction(riskAssessment);
      const timeToFix = this.getTimeToFix(riskAssessment);
      const effort = this.getEffort(issue);

      prioritizedIssues.push({
        originalIssue: issue,
        riskAssessment,
        priorityScore,
        recommendedAction,
        timeToFix,
        effort
      });
    }

    // Sort by priority score (highest first)
    return prioritizedIssues.sort((a, b) => b.priorityScore - a.priorityScore);
  }

  private async assessRisk(issue: any, context: any): Promise<RiskAssessment> {
    const baseRisk = this.getBaseRiskLevel(issue);
    const contextMultiplier = this.getContextMultiplier(context);
    const impact = this.assessImpact(issue, context);
    const likelihood = this.assessLikelihood(issue, context);
    const confidence = this.calculateConfidence(issue, context);

    const riskLevel = this.calculateRiskLevel(baseRisk, contextMultiplier, impact, likelihood);
    const priority = this.calculatePriority(riskLevel, impact, likelihood);

    return {
      riskLevel,
      confidence,
      impact,
      likelihood,
      context: this.getContextDescription(context),
      priority,
      explanation: this.generateExplanation(issue, riskLevel, impact, likelihood),
      remediation: this.getRemediation(issue),
      businessImpact: this.assessBusinessImpact(issue, context),
      technicalImpact: this.assessTechnicalImpact(issue)
    };
  }

  private getBaseRiskLevel(issue: any): 'critical' | 'high' | 'medium' | 'low' {
    if (issue.severity) {
      return issue.severity;
    }

    // Default risk assessment based on issue type
    const highRiskTypes = ['eval', 'dynamic_code', 'sql_injection', 'xss', 'reverse_shell'];
    const mediumRiskTypes = ['xor', 'base64', 'obfuscated', 'file_download'];
    const lowRiskTypes = ['configuration', 'best_practice'];

    if (highRiskTypes.includes(issue.type)) {
      return 'high';
    } else if (mediumRiskTypes.includes(issue.type)) {
      return 'medium';
    } else if (lowRiskTypes.includes(issue.type)) {
      return 'low';
    }

    return 'medium';
  }

  private getContextMultiplier(context: any): number {
    let multiplier = 1.0;

    // Environment factors
    if (context.environment === 'production') {
      multiplier *= this.riskFactors.production;
    }
    if (context.environment === 'development') {
      multiplier *= this.riskFactors.development;
    }

    // Exposure factors
    if (context.publiclyExposed) {
      multiplier *= this.riskFactors.publicExposure;
    }
    if (context.networkExposed) {
      multiplier *= this.riskFactors.networkExposed;
    }

    // Data sensitivity
    if (context.dataSensitive) {
      multiplier *= this.riskFactors.dataSensitive;
    }

    // User input handling
    if (context.handlesUserInput) {
      multiplier *= this.riskFactors.userInput;
    }

    // Authentication context
    if (context.authenticationRequired) {
      multiplier *= this.riskFactors.authentication;
    }

    return multiplier;
  }

  private assessImpact(issue: any, context: any): 'severe' | 'moderate' | 'minor' {
    // Check for data breach potential
    if (issue.type === 'secret' || issue.type === 'api_key') {
      return 'severe';
    }

    // Check for system compromise
    if (issue.type === 'eval' || issue.type === 'dynamic_code' || issue.type === 'reverse_shell') {
      return 'severe';
    }

    // Check for service disruption
    if (issue.type === 'sql_injection' || issue.type === 'xss') {
      return 'moderate';
    }

    // Check context for additional impact factors
    if (context.production && context.criticalService) {
      return 'severe';
    }

    if (context.userFacing) {
      return 'moderate';
    }

    return 'minor';
  }

  private assessLikelihood(issue: any, context: any): 'very_likely' | 'likely' | 'unlikely' | 'very_unlikely' {
    // Known vulnerabilities are more likely to be exploited
    if (issue.cve || issue.knownVulnerability) {
      return 'very_likely';
    }

    // Public exposure increases likelihood
    if (context.publiclyExposed) {
      return 'likely';
    }

    // Active exploitation patterns
    if (issue.type === 'eval' || issue.type === 'reverse_shell') {
      return 'likely';
    }

    // Weak controls increase likelihood
    if (context.weakControls) {
      return 'likely';
    }

    // Complex attacks are less likely
    if (issue.type === 'obfuscated' || issue.type === 'xor') {
      return 'unlikely';
    }

    return 'unlikely';
  }

  private calculateConfidence(issue: any, context: any): number {
    let confidence = 0.5; // Base confidence

    // High confidence for clear patterns
    if (issue.type === 'eval' || issue.type === 'secret') {
      confidence += 0.3;
    }

    // Medium confidence for suspicious patterns
    if (issue.type === 'xor' || issue.type === 'base64') {
      confidence += 0.2;
    }

    // Context increases confidence
    if (context.production) {
      confidence += 0.1;
    }

    if (context.userFacing) {
      confidence += 0.1;
    }

    return Math.min(confidence, 1.0);
  }

  private calculateRiskLevel(
    baseRisk: string,
    contextMultiplier: number,
    impact: string,
    likelihood: string
  ): 'critical' | 'high' | 'medium' | 'low' {
    let riskScore = 0;

    // Base risk score
    switch (baseRisk) {
      case 'critical': riskScore += 4; break;
      case 'high': riskScore += 3; break;
      case 'medium': riskScore += 2; break;
      case 'low': riskScore += 1; break;
    }

    // Impact multiplier
    switch (impact) {
      case 'severe': riskScore *= 1.5; break;
      case 'moderate': riskScore *= 1.2; break;
      case 'minor': riskScore *= 0.8; break;
    }

    // Likelihood multiplier
    switch (likelihood) {
      case 'very_likely': riskScore *= 1.5; break;
      case 'likely': riskScore *= 1.2; break;
      case 'unlikely': riskScore *= 0.8; break;
      case 'very_unlikely': riskScore *= 0.6; break;
    }

    // Apply context multiplier
    riskScore *= contextMultiplier;

    // Determine final risk level
    if (riskScore >= 6) return 'critical';
    if (riskScore >= 4) return 'high';
    if (riskScore >= 2) return 'medium';
    return 'low';
  }

  private calculatePriority(
    riskLevel: string,
    impact: string,
    likelihood: string
  ): number {
    let priority = 0;

    // Risk level weight
    switch (riskLevel) {
      case 'critical': priority += 100; break;
      case 'high': priority += 75; break;
      case 'medium': priority += 50; break;
      case 'low': priority += 25; break;
    }

    // Impact weight
    switch (impact) {
      case 'severe': priority += 50; break;
      case 'moderate': priority += 30; break;
      case 'minor': priority += 10; break;
    }

    // Likelihood weight
    switch (likelihood) {
      case 'very_likely': priority += 40; break;
      case 'likely': priority += 30; break;
      case 'unlikely': priority += 15; break;
      case 'very_unlikely': priority += 5; break;
    }

    return priority;
  }

  private calculatePriorityScore(riskAssessment: RiskAssessment): number {
    return riskAssessment.priority * riskAssessment.confidence;
  }

  private getRecommendedAction(riskAssessment: RiskAssessment): string {
    if (riskAssessment.riskLevel === 'critical') {
      return 'Fix immediately - Stop deployment if in production';
    } else if (riskAssessment.riskLevel === 'high') {
      return 'Fix within 24 hours';
    } else if (riskAssessment.riskLevel === 'medium') {
      return 'Fix within 1 week';
    } else {
      return 'Fix when convenient';
    }
  }

  private getTimeToFix(riskAssessment: RiskAssessment): 'immediate' | 'high' | 'medium' | 'low' {
    if (riskAssessment.riskLevel === 'critical') {
      return 'immediate';
    } else if (riskAssessment.riskLevel === 'high') {
      return 'high';
    } else if (riskAssessment.riskLevel === 'medium') {
      return 'medium';
    } else {
      return 'low';
    }
  }

  private getEffort(issue: any): 'high' | 'medium' | 'low' {
    // Estimate effort based on issue type
    const highEffortTypes = ['architecture_change', 'refactoring', 'dependency_update'];
    const mediumEffortTypes = ['code_review', 'testing', 'documentation'];
    const lowEffortTypes = ['simple_fix', 'configuration_change'];

    if (highEffortTypes.includes(issue.type)) {
      return 'high';
    } else if (mediumEffortTypes.includes(issue.type)) {
      return 'medium';
    } else if (lowEffortTypes.includes(issue.type)) {
      return 'low';
    }

    return 'medium';
  }

  private getContextDescription(context: any): string {
    const factors = [];

    if (context.environment) {
      factors.push(`Environment: ${context.environment}`);
    }
    if (context.publiclyExposed) {
      factors.push('Publicly exposed');
    }
    if (context.dataSensitive) {
      factors.push('Handles sensitive data');
    }
    if (context.userFacing) {
      factors.push('User-facing component');
    }

    return factors.length > 0 ? factors.join(', ') : 'Standard context';
  }

  private generateExplanation(
    issue: any,
    riskLevel: string,
    impact: string,
    likelihood: string
  ): string {
    return `This ${issue.type} issue has been assessed as ${riskLevel} risk with ${impact} impact and ${likelihood} likelihood of exploitation. The combination of these factors requires immediate attention.`;
  }

  private getRemediation(issue: any): string {
    if (issue.remediation) {
      return issue.remediation;
    }

    // Default remediations based on issue type
    const defaultRemediations: { [key: string]: string } = {
      'eval': 'Replace eval() with safer alternatives like JSON.parse() or specific parsing functions',
      'sql_injection': 'Use parameterized queries or ORM to prevent SQL injection',
      'xss': 'Sanitize user input and use proper output encoding',
      'secret': 'Move secrets to environment variables or secure secret management systems',
      'reverse_shell': 'Remove or secure any reverse shell connections',
      'xor': 'Review XOR operations for potential obfuscation and ensure legitimate use',
      'base64': 'Verify base64 encoding is used for legitimate purposes only'
    };

    return defaultRemediations[issue.type] || 'Review and fix according to security best practices';
  }

  private assessBusinessImpact(issue: any, context: any): string {
    if (context.production && context.criticalService) {
      return 'High - Could affect business operations and customer trust';
    }
    if (context.userFacing) {
      return 'Medium - Could affect user experience and brand reputation';
    }
    if (context.internal) {
      return 'Low - Limited business impact';
    }
    return 'Minimal - No direct business impact';
  }

  private assessTechnicalImpact(issue: any): string {
    const technicalImpacts: { [key: string]: string } = {
      'eval': 'High - Could lead to arbitrary code execution',
      'sql_injection': 'High - Could lead to data breach or system compromise',
      'xss': 'Medium - Could lead to session hijacking or data theft',
      'secret': 'High - Could lead to credential compromise',
      'reverse_shell': 'Critical - Could lead to complete system compromise',
      'xor': 'Low - Could indicate obfuscated malicious code',
      'base64': 'Low - Could be used for data hiding'
    };

    return technicalImpacts[issue.type] || 'Unknown technical impact';
  }

  async generateRiskReport(prioritizedIssues: PrioritizedIssue[]): Promise<string> {
    const criticalIssues = prioritizedIssues.filter(issue => issue.riskAssessment.riskLevel === 'critical');
    const highIssues = prioritizedIssues.filter(issue => issue.riskAssessment.riskLevel === 'high');
    const mediumIssues = prioritizedIssues.filter(issue => issue.riskAssessment.riskLevel === 'medium');
    const lowIssues = prioritizedIssues.filter(issue => issue.riskAssessment.riskLevel === 'low');

    return `
# Security Risk Assessment Report

## Executive Summary
- **Critical Issues**: ${criticalIssues.length}
- **High Priority Issues**: ${highIssues.length}
- **Medium Priority Issues**: ${mediumIssues.length}
- **Low Priority Issues**: ${lowIssues.length}

## Critical Issues (Fix Immediately)
${criticalIssues.map(issue => `
### ${issue.originalIssue.type} - Line ${issue.originalIssue.line}
- **Risk Level**: ${issue.riskAssessment.riskLevel}
- **Impact**: ${issue.riskAssessment.impact}
- **Likelihood**: ${issue.riskAssessment.likelihood}
- **Confidence**: ${(issue.riskAssessment.confidence * 100).toFixed(1)}%
- **Priority Score**: ${issue.priorityScore.toFixed(1)}
- **Recommended Action**: ${issue.recommendedAction}
- **Explanation**: ${issue.riskAssessment.explanation}
- **Business Impact**: ${issue.riskAssessment.businessImpact}
- **Technical Impact**: ${issue.riskAssessment.technicalImpact}
- **Remediation**: ${issue.riskAssessment.remediation}
`).join('')}

## High Priority Issues (Fix within 24 hours)
${highIssues.map(issue => `
### ${issue.originalIssue.type} - Line ${issue.originalIssue.line}
- **Risk Level**: ${issue.riskAssessment.riskLevel}
- **Priority Score**: ${issue.priorityScore.toFixed(1)}
- **Recommended Action**: ${issue.recommendedAction}
- **Remediation**: ${issue.riskAssessment.remediation}
`).join('')}

## Risk Distribution
- **Critical**: ${criticalIssues.length} (${((criticalIssues.length / prioritizedIssues.length) * 100).toFixed(1)}%)
- **High**: ${highIssues.length} (${((highIssues.length / prioritizedIssues.length) * 100).toFixed(1)}%)
- **Medium**: ${mediumIssues.length} (${((mediumIssues.length / prioritizedIssues.length) * 100).toFixed(1)}%)
- **Low**: ${lowIssues.length} (${((lowIssues.length / prioritizedIssues.length) * 100).toFixed(1)}%)

## Recommendations
1. **Immediate Actions**: Address all critical issues before any deployment
2. **Short-term**: Fix high priority issues within 24 hours
3. **Medium-term**: Address medium priority issues within 1 week
4. **Long-term**: Implement security controls to prevent similar issues
`;
  }
} 