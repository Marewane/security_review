// ===== app.js =====
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { body, validationResult, matchedData } = require('express-validator');

const app = express();

// ----- Fake user database -----
let users = []; // { username, hashpassword }

// ----- Middleware -----
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: 'my_secret_code',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 600000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// ----- Passport Local Strategy -----
passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = users.find(u => u.username === username);
    if (!user) return done(null, false, { message: 'User not found' });

    const match = await bcrypt.compare(password, user.hashpassword);
    if (!match) return done(null, false, { message: 'Incorrect password' });

    return done(null, user);
  }
));

// Serialize user id to session
passport.serializeUser((user, done) => done(null, user.username));

// Deserialize user from session
passport.deserializeUser((username, done) => {
  const user = users.find(u => u.username === username);
  if (!user) return done(new Error('User not found'));
  done(null, user);
});

// ----- Validation -----
function validationRegister() {
  return [
    body('username')
      .trim()
      .notEmpty().withMessage('Username is required')
      .isAlphanumeric().withMessage('Username must be letters/numbers')
      .isLength({ min: 4 }).withMessage('Username must be at least 4 chars')
      .custom(value => {
        if (users.find(u => u.username === value)) throw new Error('Username exists');
        return true;
      }),
    body('password')
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 5 }).withMessage('Password must be at least 5 chars')
  ];
}

function validationLogin() {
  return [
    body('username').notEmpty().withMessage('Username required'),
    body('password').notEmpty().withMessage('Password required')
  ];
}

// ----- Auth Middleware -----
function checkAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ----- Routes -----
// Register Form
app.get('/register', (req, res) => {
  res.send(`
    <h2>Register</h2>
    <form action="/register" method="POST">
      <input type="text" name="username" placeholder="Username" required/><br/>
      <input type="password" name="password" placeholder="Password" required/><br/>
      <button type="submit">Register</button>
    </form>
    <a href="/login">Login</a>
  `);
});

// Handle Registration
app.post('/register', validationRegister(), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.send(`<h3>Errors:</h3><ul>${errors.array().map(e => `<li>${e.msg}</li>`).join('')}</ul><a href="/register">Back</a>`);
  }

  const { username, password } = matchedData(req);
  const hashpassword = await bcrypt.hash(password, 10);
  users.push({ username, hashpassword });
  res.redirect('/login');
});

// Login Form
app.get('/login', (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form action="/login" method="POST">
      <input type="text" name="username" placeholder="Username" required/><br/>
      <input type="password" name="password" placeholder="Password" required/><br/>
      <button type="submit">Login</button>
    </form>
    <a href="/register">Register</a>
  `);
});



// Handle Login
app.post('/login', validationLogin(), (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.send(`<h3>Errors:</h3><ul>${errors.array().map(e=>`<li>${e.msg}</li>`).join('')}</ul><a href="/login">Back</a>`);

  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.send(`<h3>Login failed: ${info.message}</h3><a href="/login">Back</a>`);

    req.logIn(user, err => {
      if (err) return next(err);
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});


// Dashboard (Protected)
app.get('/dashboard', checkAuth, (req, res) => {
  res.send(`
    <h1>Welcome, ${req.user.username}!</h1>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/login');
  });
});

// Start server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
