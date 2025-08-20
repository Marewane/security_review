const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // allow frontend JS to talk to backend

const SECRET_KEY = "your_secret_key"; // keep safe!

// Mock login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === "moo" && password === "1234") {
    const token = jwt.sign(
      { username: username, role: "user" },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    return res.json({ token });
  }
  res.status(401).json({ message: "Invalid credentials" });
});

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.json({
    message: "This is protected data",
    user: req.user
  });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
