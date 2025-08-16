import * as vscode from 'vscode';

export interface SecurityLesson {
  id: string;
  title: string;
  description: string;
  category: 'authentication' | 'authorization' | 'input_validation' | 'output_sanitization' | 'encryption' | 'secure_coding' | 'owasp' | 'best_practices';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  content: string;
  examples: SecurityExample[];
  quiz: SecurityQuiz[];
  resources: SecurityResource[];
}

export interface SecurityExample {
  id: string;
  title: string;
  description: string;
  vulnerableCode: string;
  secureCode: string;
  explanation: string;
  language: string;
}

export interface SecurityQuiz {
  id: string;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface SecurityResource {
  title: string;
  url: string;
  type: 'documentation' | 'video' | 'article' | 'tool';
  description: string;
}

export interface TrainingProgress {
  userId: string;
  completedLessons: string[];
  quizScores: { [lessonId: string]: number };
  totalTimeSpent: number;
  certificates: string[];
}

export class TrainingModule {
  private lessons: SecurityLesson[] = [];
  private userProgress: TrainingProgress | null = null;

  constructor() {
    this.initializeLessons();
  }

  private initializeLessons() {
    this.lessons = [
      {
        id: 'sql-injection-basics',
        title: 'SQL Injection Fundamentals',
        description: 'Learn about SQL injection attacks and how to prevent them',
        category: 'input_validation',
        difficulty: 'beginner',
        content: `
# SQL Injection Fundamentals

SQL injection is one of the most dangerous web application vulnerabilities. It occurs when user input is directly concatenated into SQL queries without proper sanitization.

## What is SQL Injection?

SQL injection allows attackers to manipulate database queries by injecting malicious SQL code through user input. This can lead to:
- Unauthorized data access
- Data manipulation
- Database structure disclosure
- Complete system compromise

## Common Attack Vectors

1. **Login Forms**: Attackers can bypass authentication
2. **Search Functions**: Attackers can extract sensitive data
3. **URL Parameters**: Attackers can manipulate query strings
4. **Form Inputs**: Attackers can inject malicious code

## Prevention Techniques

1. **Parameterized Queries**: Use prepared statements
2. **Input Validation**: Validate and sanitize all input
3. **Least Privilege**: Use database accounts with minimal permissions
4. **Error Handling**: Don't expose database errors to users
        `,
        examples: [
          {
            id: 'vulnerable-login',
            title: 'Vulnerable Login Form',
            description: 'A login form vulnerable to SQL injection',
            vulnerableCode: `
// VULNERABLE CODE
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
  
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});
            `,
            secureCode: `
// SECURE CODE
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  
  db.query(query, [username, password], (err, results) => {
    if (results.length > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});
            `,
            explanation: 'The secure version uses parameterized queries with placeholders (?) instead of string concatenation. This prevents SQL injection by treating user input as data rather than code.',
            language: 'javascript'
          }
        ],
        quiz: [
          {
            id: 'sql-quiz-1',
            question: 'What is the primary defense against SQL injection?',
            options: [
              'Input validation',
              'Parameterized queries',
              'Output encoding',
              'Rate limiting'
            ],
            correctAnswer: 1,
            explanation: 'Parameterized queries (prepared statements) are the most effective defense against SQL injection as they separate data from code.',
            difficulty: 'easy'
          },
          {
            id: 'sql-quiz-2',
            question: 'Which of the following is vulnerable to SQL injection?',
            options: [
              'SELECT * FROM users WHERE id = ?',
              'SELECT * FROM users WHERE id = ${id}',
              'SELECT * FROM users WHERE id = parseInt(id)',
              'SELECT * FROM users WHERE id = escape(id)'
            ],
            correctAnswer: 1,
            explanation: 'Template literals with user input are vulnerable to SQL injection. Only parameterized queries are safe.',
            difficulty: 'medium'
          }
        ],
        resources: [
          {
            title: 'OWASP SQL Injection Prevention',
            url: 'https://owasp.org/www-community/attacks/SQL_Injection',
            type: 'documentation',
            description: 'Comprehensive guide to SQL injection prevention'
          },
          {
            title: 'SQL Injection Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            type: 'documentation',
            description: 'Quick reference for SQL injection prevention'
          }
        ]
      },
      {
        id: 'xss-prevention',
        title: 'Cross-Site Scripting (XSS) Prevention',
        description: 'Learn about XSS attacks and how to prevent them',
        category: 'output_sanitization',
        difficulty: 'beginner',
        content: `
# Cross-Site Scripting (XSS) Prevention

XSS attacks occur when malicious scripts are injected into web pages and executed in users' browsers.

## Types of XSS

1. **Reflected XSS**: Malicious script is reflected from the server
2. **Stored XSS**: Malicious script is stored in the database
3. **DOM XSS**: Malicious script manipulates the DOM

## Prevention Techniques

1. **Output Encoding**: Encode all user input before output
2. **Content Security Policy**: Restrict script execution
3. **Input Validation**: Validate and sanitize input
4. **HttpOnly Cookies**: Prevent cookie access via JavaScript
        `,
        examples: [
          {
            id: 'vulnerable-comment',
            title: 'Vulnerable Comment System',
            description: 'A comment system vulnerable to XSS',
            vulnerableCode: `
// VULNERABLE CODE
app.post('/comment', (req, res) => {
  const { comment } = req.body;
  const html = \`<div class="comment">\${comment}</div>\`;
  
  // Store comment in database
  db.query('INSERT INTO comments (content) VALUES (?)', [html]);
  res.json({ success: true });
});

// Display comments
app.get('/comments', (req, res) => {
  db.query('SELECT content FROM comments', (err, results) => {
    const comments = results.map(row => row.content).join('');
    res.send(\`<div id="comments">\${comments}</div>\`);
  });
});
            `,
            secureCode: `
// SECURE CODE
app.post('/comment', (req, res) => {
  const { comment } = req.body;
  
  // Store raw comment in database
  db.query('INSERT INTO comments (content) VALUES (?)', [comment]);
  res.json({ success: true });
});

// Display comments
app.get('/comments', (req, res) => {
  db.query('SELECT content FROM comments', (err, results) => {
    const comments = results.map(row => {
      // Encode output to prevent XSS
      return \`<div class="comment">\${escapeHtml(row.content)}</div>\`;
    }).join('');
    res.send(\`<div id="comments">\${comments}</div>\`);
  });
});

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
            `,
            explanation: 'The secure version stores raw data and encodes it only when displaying. This prevents XSS by ensuring user input is treated as data, not code.',
            language: 'javascript'
          }
        ],
        quiz: [
          {
            id: 'xss-quiz-1',
            question: 'What is the best defense against XSS?',
            options: [
              'Input validation',
              'Output encoding',
              'HTTPS',
              'Rate limiting'
            ],
            correctAnswer: 1,
            explanation: 'Output encoding is the primary defense against XSS as it prevents malicious scripts from being executed.',
            difficulty: 'easy'
          }
        ],
        resources: [
          {
            title: 'OWASP XSS Prevention',
            url: 'https://owasp.org/www-community/attacks/xss/',
            type: 'documentation',
            description: 'Comprehensive guide to XSS prevention'
          }
        ]
      },
      {
        id: 'authentication-security',
        title: 'Secure Authentication Implementation',
        description: 'Learn about secure authentication practices',
        category: 'authentication',
        difficulty: 'intermediate',
        content: `
# Secure Authentication Implementation

Authentication is the process of verifying user identity. Poor authentication can lead to unauthorized access.

## Best Practices

1. **Strong Password Policies**: Enforce complex passwords
2. **Multi-Factor Authentication**: Require additional verification
3. **Secure Session Management**: Use secure session tokens
4. **Password Hashing**: Use bcrypt or similar
5. **Rate Limiting**: Prevent brute force attacks
6. **Account Lockout**: Lock accounts after failed attempts

## Common Vulnerabilities

1. **Weak Passwords**: Easily guessable passwords
2. **Session Hijacking**: Stolen session tokens
3. **Brute Force**: Automated password guessing
4. **Credential Stuffing**: Using leaked credentials
        `,
        examples: [
          {
            id: 'weak-auth',
            title: 'Weak Authentication',
            description: 'Insecure authentication implementation',
            vulnerableCode: `
// VULNERABLE CODE
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Plain text password comparison
  db.query('SELECT * FROM users WHERE username = ? AND password = ?', 
    [username, password], (err, results) => {
    if (results.length > 0) {
      // Weak session management
      req.session.userId = results[0].id;
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});
            `,
            secureCode: `
// SECURE CODE
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Rate limiting
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Too many attempts' });
  }
  
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (results.length > 0) {
      const user = results[0];
      
      // Secure password verification
      bcrypt.compare(password, user.password_hash, (err, isMatch) => {
        if (isMatch) {
          // Secure session management
          const sessionToken = generateSecureToken();
          req.session.userId = user.id;
          req.session.token = sessionToken;
          
          res.json({ success: true });
        } else {
          // Log failed attempt
          logFailedAttempt(req.ip, username);
          res.json({ success: false });
        }
      });
    } else {
      res.json({ success: false });
    }
  });
});
            `,
            explanation: 'The secure version uses bcrypt for password hashing, implements rate limiting, and uses secure session tokens.',
            language: 'javascript'
          }
        ],
        quiz: [
          {
            id: 'auth-quiz-1',
            question: 'What is the recommended password hashing algorithm?',
            options: [
              'MD5',
              'SHA-1',
              'bcrypt',
              'Base64'
            ],
            correctAnswer: 2,
            explanation: 'bcrypt is designed specifically for password hashing and includes salt and cost factors.',
            difficulty: 'medium'
          }
        ],
        resources: [
          {
            title: 'OWASP Authentication Cheat Sheet',
            url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            type: 'documentation',
            description: 'Authentication security best practices'
          }
        ]
      }
    ];
  }

  async getLessons(category?: string, difficulty?: string): Promise<SecurityLesson[]> {
    let filteredLessons = this.lessons;

    if (category) {
      filteredLessons = filteredLessons.filter(lesson => lesson.category === category);
    }

    if (difficulty) {
      filteredLessons = filteredLessons.filter(lesson => lesson.difficulty === difficulty);
    }

    return filteredLessons;
  }

  async getLesson(lessonId: string): Promise<SecurityLesson | null> {
    return this.lessons.find(lesson => lesson.id === lessonId) || null;
  }

  async getExamples(lessonId: string): Promise<SecurityExample[]> {
    const lesson = await this.getLesson(lessonId);
    return lesson?.examples || [];
  }

  async getQuiz(lessonId: string): Promise<SecurityQuiz[]> {
    const lesson = await this.getLesson(lessonId);
    return lesson?.quiz || [];
  }

  async getResources(lessonId: string): Promise<SecurityResource[]> {
    const lesson = await this.getLesson(lessonId);
    return lesson?.resources || [];
  }

  async submitQuizAnswer(lessonId: string, questionId: string, answer: number): Promise<boolean> {
    const lesson = await this.getLesson(lessonId);
    const question = lesson?.quiz.find(q => q.id === questionId);
    
    if (!question) {
      return false;
    }

    return answer === question.correctAnswer;
  }

  async calculateQuizScore(lessonId: string, answers: { [questionId: string]: number }): Promise<number> {
    const lesson = await this.getLesson(lessonId);
    if (!lesson) {
      return 0;
    }

    let correctAnswers = 0;
    let totalQuestions = lesson.quiz.length;

    for (const [questionId, answer] of Object.entries(answers)) {
      const question = lesson.quiz.find(q => q.id === questionId);
      if (question && answer === question.correctAnswer) {
        correctAnswers++;
      }
    }

    return (correctAnswers / totalQuestions) * 100;
  }

  async markLessonComplete(lessonId: string): Promise<void> {
    if (!this.userProgress) {
      this.userProgress = {
        userId: 'default',
        completedLessons: [],
        quizScores: {},
        totalTimeSpent: 0,
        certificates: []
      };
    }

    if (!this.userProgress.completedLessons.includes(lessonId)) {
      this.userProgress.completedLessons.push(lessonId);
    }
  }

  async getProgress(): Promise<TrainingProgress | null> {
    return this.userProgress;
  }

  async generateCertificate(lessonId: string): Promise<string> {
    const lesson = await this.getLesson(lessonId);
    if (!lesson) {
      throw new Error('Lesson not found');
    }

    const certificate = `
# Security Training Certificate

**Student**: ${this.userProgress?.userId || 'Anonymous'}
**Lesson**: ${lesson.title}
**Category**: ${lesson.category}
**Difficulty**: ${lesson.difficulty}
**Date**: ${new Date().toISOString().split('T')[0]}

This certificate confirms successful completion of the "${lesson.title}" security training module.

**Topics Covered**:
- ${lesson.description}

**Certificate ID**: ${lessonId}-${Date.now()}
    `;

    if (this.userProgress) {
      this.userProgress.certificates.push(lessonId);
    }

    return certificate;
  }

  async getRecommendedLessons(): Promise<SecurityLesson[]> {
    if (!this.userProgress) {
      return this.lessons.filter(lesson => lesson.difficulty === 'beginner').slice(0, 3);
    }

    const completedCategories = new Set(
      this.userProgress.completedLessons.map(id => 
        this.lessons.find(l => l.id === id)?.category
      ).filter(Boolean)
    );

    // Recommend lessons in categories not yet completed
    const recommended = this.lessons.filter(lesson => 
      !this.userProgress!.completedLessons.includes(lesson.id) &&
      !completedCategories.has(lesson.category)
    );

    return recommended.slice(0, 3);
  }

  generateTrainingReport(): string {
    if (!this.userProgress) {
      return 'No training progress available.';
    }

    const completedLessons = this.userProgress.completedLessons.length;
    const totalLessons = this.lessons.length;
    const progressPercentage = (completedLessons / totalLessons) * 100;

    const averageScore = Object.values(this.userProgress.quizScores).length > 0
      ? Object.values(this.userProgress.quizScores).reduce((a, b) => a + b, 0) / Object.values(this.userProgress.quizScores).length
      : 0;

    return `
# Security Training Progress Report

## Overall Progress
- **Completed Lessons**: ${completedLessons}/${totalLessons}
- **Progress**: ${progressPercentage.toFixed(1)}%
- **Average Quiz Score**: ${averageScore.toFixed(1)}%
- **Total Time Spent**: ${this.userProgress.totalTimeSpent} minutes
- **Certificates Earned**: ${this.userProgress.certificates.length}

## Completed Lessons
${this.userProgress.completedLessons.map(lessonId => {
  const lesson = this.lessons.find(l => l.id === lessonId);
  return `- ${lesson?.title || lessonId}`;
}).join('\n')}

## Quiz Performance
${Object.entries(this.userProgress.quizScores).map(([lessonId, score]) => {
  const lesson = this.lessons.find(l => l.id === lessonId);
  return `- ${lesson?.title || lessonId}: ${score.toFixed(1)}%`;
}).join('\n')}

## Recommendations
${this.getRecommendations()}
    `;
  }

  private getRecommendations(): string {
    if (!this.userProgress) {
      return 'Start with beginner lessons to build a strong foundation.';
    }

    const recommendations = [];

    if (this.userProgress.completedLessons.length < 3) {
      recommendations.push('Complete more beginner lessons to build a strong foundation.');
    }

    const lowScores = Object.entries(this.userProgress.quizScores)
      .filter(([_, score]) => score < 70)
      .map(([lessonId, _]) => this.lessons.find(l => l.id === lessonId)?.title)
      .filter(Boolean);

    if (lowScores.length > 0) {
      recommendations.push(`Review lessons with low quiz scores: ${lowScores.join(', ')}`);
    }

    const completedCategories = new Set(
      this.userProgress.completedLessons.map(id => 
        this.lessons.find(l => l.id === id)?.category
      ).filter(Boolean)
    );

    const missingCategories = ['authentication', 'authorization', 'input_validation', 'output_sanitization']
      .filter(category => !completedCategories.has(category as any));

    if (missingCategories.length > 0) {
      recommendations.push(`Focus on missing categories: ${missingCategories.join(', ')}`);
    }

    return recommendations.join('\n');
  }
} 