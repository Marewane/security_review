// session-mongo-demo.js
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();

// ------------------------
// 1 Connect to MongoDB
// ------------------------
mongoose.connect('mongodb://127.0.0.1:27017/session-demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB connection error:', err));

// ------------------------
// 2 Set up session middleware
// ------------------------
app.use(session({
  secret: 'mySecretKey',                // Secret key to sign session ID
  resave: false,                         // Don't save session if not modified
  saveUninitialized: false,              // Only save sessions with data
  store: MongoStore.create({ mongoUrl: 'mongodb://127.0.0.1:27017/session-demo' }),
  cookie: { maxAge: 6000000 },             // 1 minute
}));

// ------------------------
// 3 Routes
// ------------------------

// Home route: count visits
app.get('/', (req, res) => {
  res.send('welcome in testing sessions and cookies')
});

// Login route: simulate user login
app.get('/login', (req, res) => {
  req.session.userId = 123; // store user id in session
  res.send('Logged in! Your session now has a userId.');
  res.on('finish',()=>{
    const setCookie = res.getHeader('Set-Cookie');
    if(setCookie){
        console.log(setCookie);
    }else{
        console.log('no cookies here');
    }
  })
});

// Profile route: check if user is logged in
app.get('/profile', (req, res) => {
    console.log(req.session);
  if (req.session.userId) {
    res.send(`Welcome user ${req.session.userId}`);
  } else {
    res.send('Please log in first.');
  }
    
});

// Logout route: destroy session
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.send('Error logging out.');
    res.clearCookie('connect.sid');
    res.send('Logged out. Session destroyed!');
  });
});

app.get('/age',(req,res)=>{
  req.session.age = 21;
  res.send('this is route for tesing adding age to session database');
});

// ------------------------
// 4 Start server
// ------------------------
app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
