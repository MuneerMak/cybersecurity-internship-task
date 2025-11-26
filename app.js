const logger = require('./logger');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const SECRET_KEY = 'your-secret-key-change-this';
const bcrypt = require('bcrypt');
const validator = require('validator');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Fake user database (intentionally vulnerable)
let users = [];

// Home page
app.get('/', (req, res) => {
    res.send('<h1>Welcome to Vulnerable App</h1><a href="/signup">Signup</a> | <a href="/login">Login</a>');
});

// Signup page (VULNERABLE - No input validation)
app.post('/signup', async (req, res) => {
    
    let { username, email, password } = req.body;
    logger.info(`New user registered: ${username}`);
    // Validation (from previous step)
    if (!validator.isEmail(email)) {
        return res.status(400).send('Invalid email format');
    }
    
    username = validator.escape(username);
    
    if (password.length < 8) {
        return res.status(400).send('Password must be at least 8 characters');
    }
    
    // FIXED: Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    users.push({ username, email, password: hashedPassword });
    
    res.send(`User ${username} registered! <a href="/login">Login</a>`);
});

app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;
    
    // VULNERABILITY: Password stored in plain text
    users.push({ username, email, password });
    
    res.send(`User ${username} registered! <a href="/login">Login</a>`);
});

// Login page (VULNERABLE - SQL Injection possible simulation)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        logger.info(`User logged in: ${username}`);
        // FIXED: Generate JWT token
        const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        
        res.send(`
            Welcome ${username}! 
            <p>Your token: ${token}</p>
            <a href="/profile/${username}">View Profile</a>
        `);
    } else {
        logger.warn(`Failed login attempt for username: ${username}`);
        res.send('Invalid credentials! <a href="/login">Try again</a>');
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABILITY: No input sanitization (XSS possible)
    // VULNERABILITY: Weak authentication logic
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        res.send(`Welcome ${username}! <a href="/profile/${username}">View Profile</a>`);
    } else {
        res.send('Invalid credentials! <a href="/login">Try again</a>');
    }
});

// Profile page (VULNERABLE - XSS)
app.get('/profile/:username', (req, res) => {
    const { username } = req.params;
    const user = users.find(u => u.username === username);
    
    if (user) {
        // VULNERABILITY: Displaying user input without sanitization (XSS)
        res.send(`
            <h2>Profile: ${user.username}</h2>
            <p>Email: ${user.email}</p>
            <p>Password: ${user.password}</p>
        `);
    } else {
        res.send('User not found');
    }
});

app.listen(3000, () => {
    logger.info('Application started on http://localhost:3000');
    console.log('Vulnerable app running on http://localhost:3000');
});