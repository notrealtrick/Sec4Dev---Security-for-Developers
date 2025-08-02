// Test file to demonstrate Sec4Dev Security Scanner capabilities (v1.0.0)

// ===== HIGH RISK - Direct eval usage =====
const dangerousEval = eval("console.log('This is dangerous')");

// ===== HIGH RISK - Function constructor with string =====
const dangerousFunction = new Function("console.log('Also dangerous')");

// ===== HIGH RISK - setTimeout with string code =====
setTimeout("alert('Dangerous code execution')", 1000);

// ===== HIGH RISK - setInterval with string code =====
setInterval("console.log('Another dangerous pattern')", 2000);

// ===== MEDIUM RISK - XOR obfuscation =====
const key = 0x42;
const encrypted = "Hello World".split('').map(char => char.charCodeAt(0) ^ key);
const decrypted = encrypted.map(code => String.fromCharCode(code ^ key));

// ===== MEDIUM RISK - Base64 encoding/decoding =====
const encoded = btoa("Suspicious data");
const decoded = atob("SGVsbG8gV29ybGQ=");

// ===== MEDIUM RISK - Buffer with base64 =====
const buffer = Buffer.from("Hello World", "base64");

// ===== MEDIUM RISK - TextDecoder/TextEncoder =====
const decoder = new TextDecoder();
const encoder = new TextEncoder();

// ===== LOW RISK - Unescape usage =====
const unescaped = unescape("%48%65%6C%6C%6F");

// ===== LOW RISK - DecodeURIComponent =====
const decodedURI = decodeURIComponent("Hello%20World");

// ===== LOW RISK - String.fromCharCode =====
const charCode = String.fromCharCode(72, 101, 108, 108, 111);

// ===== HIGH RISK - Child process execution (Node.js) =====
const { exec } = require('child_process');
exec('ls -la', (error, stdout, stderr) => {
    console.log(stdout);
});

// ===== HIGH RISK - Spawn process =====
const { spawn } = require('child_process');
const child = spawn('node', ['script.js']);

// ===== MEDIUM RISK - Encryption/decryption functions =====
function encrypt(data, key) {
    return data.split('').map(char => char.charCodeAt(0) ^ key);
}

function decrypt(encrypted, key) {
    return encrypted.map(code => String.fromCharCode(code ^ key));
}

// ===== HIGH RISK - Hardcoded secrets (NEW FEATURE) =====
const apiKey = "sk-1234567890abcdef1234567890abcdef";
const password = "mypassword123";
const databaseUrl = "mongodb://user:pass@localhost:27017/db";
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// ===== HIGH RISK - SQL Injection patterns (OWASP A03) =====
const userInput = "'; DROP TABLE users; --";
const sqlQuery = "SELECT * FROM users WHERE id = " + userInput;

// ===== HIGH RISK - XSS patterns (OWASP A03) =====
const userData = "<script>alert('XSS')</script>";
document.getElementById("content").innerHTML = userData;
document.write(userData);

// ===== MEDIUM RISK - CSRF patterns (OWASP A01) =====
const csrfToken = "weak_token_123";
const rememberMe = true;

// ===== MEDIUM RISK - Insecure configuration (OWASP A05) =====
const corsOrigin = "*";
const httpsEnabled = false;
const debugMode = true;

// ===== MEDIUM RISK - Localhost references (OWASP A04) =====
const apiUrl = "http://localhost:3000/api";
const dbHost = "127.0.0.1";

// ===== LOW RISK - Console logging in production =====
console.log("User data:", { id: 123, name: "John" });
console.error("Error occurred:", error);

// ===== SAFE ALTERNATIVES =====
// Instead of eval(), use JSON.parse() for JSON data
const jsonData = JSON.parse('{"name": "John", "age": 30}');

// Instead of eval(), use proper parsing for mathematical expressions
const result = Function('"use strict"; return (2 + 2)')();

// Instead of hardcoded secrets, use environment variables
const safeApiKey = process.env.API_KEY;
const safePassword = process.env.PASSWORD;

// Instead of string concatenation in SQL, use parameterized queries
const safeQuery = "SELECT * FROM users WHERE id = ?";

// Instead of innerHTML, use textContent
document.getElementById("content").textContent = userData;

console.log('Sec4Dev test file completed - v1.0.0'); 