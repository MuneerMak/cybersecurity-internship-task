Application Overview:
•	Application: User Management System.
•	URL: http://localhost:3000.
•	Pages tested: Signup, Login, Profile.
Vulnerabilities Found
1.	Cross-Site Scripting (XSS):
•	Severity: High 
•	Location: Signup form (username field), Profile page 
•	Description: User input is not sanitized, allowing malicious scripts to execute 
•	Proof: Injected ‘<script>alert('XSS')</script>’ successfully executed 
•	Impact: Attacker can steal cookies, session tokens, or redirect users
2.	Lack of Input Validation (SQL Injection Risk):
•	Severity: High 
•	Location: Login form 
•	Description: No input validation or sanitization on username/password fields. While this specific app doesn't use SQL, the lack of validation means a SQL-based version would be vulnerable to SQL injection. 
•	Proof: Attempted (‘admin' OR '1'='1’ ) no error handling or input filtering detected 
•	Impact: In a database-driven application, this would allow authentication bypass 
•	Current Risk: Potential for other injection attacks (NoSQL, command injection, etc.)
3.	Plain Text Password Storage:
•	Severity: Critical 
•	Location: User database 
•	Description: Passwords stored without encryption 
•	Impact: Complete account compromise if database is breached
4.	No Authentication Token
•	Severity: High 
•	Location: Login system 
•	Description: No session management or tokens 
•	Impact: Weak authentication, session hijacking possible
5.	Missing Security Headers
•	Severity: Medium 
•	Location: HTTP responses 
•	Description: No security headers like CSP, X-Frame-Options 
•	Impact: Vulnerable to clickjacking, MIME-sniffing attacks
OWASP ZAP Findings
 [OWASP ZAP Scan Results](images/OWASP-Before.jpeg)

Recommendations
•	Implement input validation and sanitization
•	Hash passwords using bcrypt 
•	Add JWT-based authentication 
•	Use Helmet.js for security headers 
•	Implement HTTPS
