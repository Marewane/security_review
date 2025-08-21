const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { body, validationResult, matchedData } = require('express-validator');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Configuration
const JWT_SECRET = 'super_secure_jwt_secret_key';
const TOKEN_EXPIRY = '30m';

// Fake "database"
const users = [
  { username: 'admin', passwordHash: bcrypt.hashSync('password123', 10) }
];

// Middleware: Authenticate via JWT from cookie
function authMiddleware(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.redirect('/login');
    }
    req.user = decoded;
    next();
  });
}

// Escape HTML to prevent XSS
function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[m]));
}


// Routes
app.get('/', (req, res) => {
  res.send('Welcome to the secure Node.js application!');
});

app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form action="/login" method="POST">
      <input name="username" placeholder="Username" required /><br><br>
      <input type="password" name="password" placeholder="Password" required /><br><br>
      <button type="submit">Login</button>
    </form>
  `);
});

// Enhanced: Sanitize & Validate Input
function loginValidation() {
  return [
    body('username')
      .trim()
      .isAlphanumeric()
      .withMessage('Username must contain only letters and numbers')
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .escape(), // HTML sanitize

    body('password')
      .trim()
      .isLength({ min: 5, max: 128 })
      .withMessage('Password must be at least 5 characters')
      .escape() // Sanitize (though password shouldn't have HTML, but safe)
  ];
}



// POST /login - Validate, sanitize, verify, issue JWT
app.post('/login', loginValidation(), (req, res) => {
  const errors = validationResult(req);

  // Improved Error Handling
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  // Use sanitized input
  const { username, password } = matchedData(req); // Only get sanitized/validated data

  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).send('Invalid username or password');
  }

  // Sanitize data BEFORE putting in JWT payload
  const sanitizedUsername = escapeHtml(username); // Prevent any injection in payload

  // Create JWT with sanitized payload
  const token = jwt.sign(
    { 
      username: sanitizedUsername // Sanitized!
    },
    JWT_SECRET,
    { 
      expiresIn: TOKEN_EXPIRY 
    }
  );

  // Set in HttpOnly cookie
  res.cookie('token', token, {
    httpOnly: true, // prevent javascript from access cookie
    secure: false, // use either http or https
    sameSite: 'lax', // prevent website from csrf attacks
    maxAge: 30 * 60 * 1000
  });

  res.redirect('/profile');
});



// GET /profile - Protected route
app.get('/profile', authMiddleware, (req, res) => {
  const safeUsername = escapeHtml(req.user.username);
  res.send(`
    <h1>Welcome, ${safeUsername}</h1>
    <p><a href="/logout">Logout</a></p>
  `);
});



// GET /logout - Clear cookie
app.get('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'lax'
  });
  res.redirect('/login');
});



// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
  });
});

// Start server
app.listen(3000, () => {
  console.log('JWT + HttpOnly Cookie App running on http://localhost:3000');
  console.log('Try logging in with username: admin, password: password123');
});