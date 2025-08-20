const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const { query,body, validationResult, matchedData } = require('express-validator');
const jwt = require('jsonwebtoken');
// const helmet = require('helmet');
const app = express();

// Middleware
// app.use(helmet()); // Secure headers
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session setup
app.use(session({
  secret: 'super_secure_secret_key',
  resave: false, 
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // set true in production with HTTPS
    sameSite: true,
    maxAge: 30 * 60 * 1000 // 30 minutes to expire the session id
  }
}));

// CSRF protection
const csrfProtection = csrf();
app.use(csrfProtection);

// Fake "database"
const users = [
  { username: 'admin', passwordHash: bcrypt.hashSync('password123', 10) } // hashed password
];

// Middleware to protect routes
function authMiddleware(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// Escape HTML to prevent XSS
function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (m) => ({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;',
    "'":'&#39;'
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
      <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
      <input name="username" placeholder="Username" required /><br>
      <input type="password" name="password" placeholder="Password" required /><br>
      <button type="submit">Login</button>
    </form>
  `);
});

function loginEndpointSanitizationAndValidation(){
  return [
    body('username').trim().isAlphanumeric().isLength({ min: 3 }),
    body('password').trim().isLength({ min: 5 })
  ];
}

app.post('/login', 
  csrfProtection, // <-- Add this explicitly
  loginEndpointSanitizationAndValidation(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.send('Invalid username or password');
    }

    const match = bcrypt.compareSync(password, user.passwordHash);
    if (!match) {
      return res.send('Invalid username or password');
    }

    req.session.user = username;
    res.redirect('/profile');
  }
);

app.get('/profile', authMiddleware, (req, res) => {
  const safeUsername = escapeHtml(req.session.user);
  res.send(`<h1>Welcome, ${safeUsername}</h1>
            <p><a href="/logout">Logout</a></p>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    res.redirect('/login');
  });
});


// testing xss
app.get('/hello',
  
  query('name').trim().isLength({min:3}).escape()
  ,(req,res)=>{
  const {name} = matchedData(req);
  res.send(`
    <h1>Hello ${name}</h1>
    `)
})
// Start server
app.listen(3000, () => console.log('Secure app running on http://localhost:3000'));
