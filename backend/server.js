const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// Database setup
const db = new sqlite3.Database("./database.sqlite");

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users(username, password) VALUES (?, ?)`,
    [username, hashedPassword],
    (err) => {
      if (err) {
        return res.json({ message: "User already exists" });
      }
      res.json({ message: "User registered successfully" });
    }
  );
});

// Login API
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user) {
        return res.json({ message: "Invalid username" });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.json({ message: "Wrong password" });
      }

      res.json({ message: "Login successful", user: username });
    }
  );
});

// Start server
app.listen(5000, () => {
  console.log("✅ Server running on http://localhost:5000");
});
