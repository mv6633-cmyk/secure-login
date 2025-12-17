const express = require("express"); const sqlite3 = require("sqlite3").verbose(); 
const bcrypt = require("bcrypt"); const cors = require("cors"); 
 
const app = express(); app.use(express.json()); app.use(cors()); 
 
// DB Setup 
const db = new sqlite3.Database("./database.sqlite"); 
 
db.run(` 
  CREATE TABLE IF NOT EXISTS users (     id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE,     password TEXT 
  ) 
`); 
db.run(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    status TEXT,
    timestamp TEXT
  )
`);

// Register 
// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ message: "Username and password required" });
  }

  // Simple strength rules: min 8 chars, at least one digit
  if (password.length < 8 || !/[0-9]/.test(password)) {
    return res.json({ message: "Weak password. Use 8+ chars with numbers." });
  }

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users(username, password) VALUES (?, ?)`,
    [username, hashed],
    (err) => {
      if (err) return res.json({ message: "User exists" });
      res.json({ message: "User registered" });
    }
  );
});

// INSECURE LOGIN (demo only – bad practice)
app.post("/login-insecure", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (!user) return res.json({ message: "Invalid user" });

      // ❌ BAD: compares plain text to hashed DB value – always fails
      // or if you stored plain text, it would be very weak.
      if (user.password !== password) {
        return res.json({ message: "Wrong password (insecure mode)" });
      }

      res.json({ message: "Login success (insecure)", user: username });
    }
  );
});

// Login 
// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user) {
        db.run(
          `INSERT INTO logs(username, action, status, timestamp)
           VALUES (?, 'login', 'invalid user', datetime('now'))`,
          [username]
        );
        return res.json({ message: "Invalid user" });
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        db.run(
          `INSERT INTO logs(username, action, status, timestamp)
           VALUES (?, 'login', 'wrong password', datetime('now'))`,
          [username]
        );
        return res.json({ message: "Wrong password" });
      }

      db.run(
        `INSERT INTO logs(username, action, status, timestamp)
         VALUES (?, 'login', 'success', datetime('now'))`,
        [username]
      );

      res.json({ message: "Login success", user: username });
    }
  );
});

// Get recent logs
app.get("/logs", (req, res) => {
  db.all(
    `SELECT username, action, status, timestamp
     FROM logs
     ORDER BY id DESC
     LIMIT 20`,
    [],
    (err, rows) => {
      if (err) return res.json([]);
      res.json(rows);
    }
  );
});

 
app.listen(3000, () => console.log("Server running on 3000")); 
