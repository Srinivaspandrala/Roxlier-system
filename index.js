const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
const db = new sqlite3.Database("./users.db");

// Middleware
app.use(cors());
app.use(express.json());

// DB Setup
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      address TEXT,
      role TEXT
    )`);
  db.run(`
    CREATE TABLE IF NOT EXISTS store (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      storeowner TEXT,
      storename TEXT,
      email TEXT,
      address TEXT,
      logo TEXT,
      FOREIGN KEY (email) REFERENCES users(email)
    )`);
  db.run(`
    CREATE TABLE IF NOT EXISTS store_ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      storename TEXT,
      rating INTEGER DEFAULT 0 CHECK(rating >= 1 AND rating <= 5),
      FOREIGN KEY (username) REFERENCES users(name) ON DELETE CASCADE
    )`);
  db.run("PRAGMA foreign_keys = ON");

  const adminEmail = process.env.adminemail;
  const adminPassword = process.env.adminpassword;
  const hashedPassword = bcrypt.hashSync(adminPassword, 8);

  db.get(`SELECT * FROM users WHERE email = ?`, [adminEmail], (err, row) => {
    if (!row) {
      db.run(
        `INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)`,
        ["System Admin", adminEmail, hashedPassword, "Admin Address", "systemadmin"],
        (err) => {
          if (err) console.error("Error inserting admin user:", err.message);
        }
      );
    }
  });
});

// JWT Middleware
function authorizeRole(requiredRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (!decoded.role || !requiredRoles.includes(decoded.role)) {
        return res.status(403).json({ error: "Forbidden" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
  };
}

// Register
app.post("/register", async (req, res) => {
  const { name, email, password, address } = req.body;
  if (!name || !email || !password || !address) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const hashedPassword = await bcrypt.hash(password, 8);
  db.run(
    `INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, 'normaluser')`,
    [name, email, hashedPassword, address],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "Error while registering user" });
      }
      res.status(201).json({ message: "User registered successfully", id: this.lastID });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid credentials" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  });
});

app.post("/changepassword", authorizeRole(["systemadmin", "normaluser"]), (req, res) => {
  const userEmail = req.user.name;
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "Both passwords are required" });
  }
  db.get("SELECT * FROM users WHERE name = ?", [userEmail], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "User not found" });
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(401).json({ message: "Current password is incorrect" });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, userEmail], (err) => {
      if (err) return res.status(500).json({ message: "Error updating password" });
      res.status(200).json({ message: "Password changed successfully!" });
    });
  });
});

// Node.js Express route
app.get("/dashboard/stats", authorizeRole(["systemadmin", "storeowner"]), async (req, res) => {
  const { role, username } = req.user;
  try {
    if (role === "storeowner") {
      const storeCount = await db.get("SELECT COUNT(*) as count FROM store WHERE storeowner = ?", [username]);
      return res.json({ role, stores: storeCount.count });
    }
    if (role === "systemadmin") {
      const userCount = await db.get("SELECT COUNT(*) as count FROM users");
      const storeCount = await db.get("SELECT COUNT(*) as count FROM store");
      const ratingCount = await db.get("SELECT COUNT(*) as count FROM store_ratings");
      return res.json({ role, users: userCount.count, stores: storeCount.count, ratings: ratingCount.count });
    }
    res.status(403).json({ error: "Access denied" });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch dashboard stats" });
  }
});

app.post("/newuser", authorizeRole(["systemadmin"]), async (req, res) => {
  const { name, email, password, address, role } = req.body;
  if (!name || !email || !password || !address) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const hashedPassword = await bcrypt.hash(password, 8);
  db.run(
    `INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)`,
    [name, email, hashedPassword, address, role],
    function (err) {
      if (err) return res.status(400).json({ message: "Error while adding user" });
      res.status(201).json({ message: "User added successfully", id: this.lastID });
    }
  );
});

app.get("/userlist", authorizeRole(["systemadmin"]), (req, res) => {
  db.all(`SELECT id, name, email, address, role FROM users`, [], (err, rows) => {
    if (err) return res.status(400).json({ message: "Error while fetching users" });
    res.json(rows);
  });
});

app.get("/stores", authorizeRole(["systemadmin", "normaluser"]), (req, res) => {
  db.all(`SELECT id, storeowner, storename, email, address FROM store`, [], (err, rows) => {
    if (err) return res.status(400).json({ message: "Error while fetching stores" });
    res.json(rows);
  });
});

app.post("/rate-store", authorizeRole(["normaluser"]), (req, res) => {
  const { storename, rating } = req.body;
  const username = req.user.name;
  if (!storename || !rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const checkQuery = `SELECT * FROM store_ratings WHERE username = ? AND storename = ?`;
  db.get(checkQuery, [username, storename], (err, row) => {
    if (err) return res.status(500).json({ message: "Error checking existing rating" });
    if (row) {
      const updateQuery = `UPDATE store_ratings SET rating = ? WHERE username = ? AND storename = ?`;
      db.run(updateQuery, [rating, username, storename], (err) => {
        if (err) return res.status(500).json({ message: "Failed to update rating" });
        res.json({ message: "Rating updated successfully" });
      });
    } else {
      const insertQuery = `INSERT INTO store_ratings (username, storename, rating) VALUES (?, ?, ?)`;
      db.run(insertQuery, [username, storename, rating], (err) => {
        if (err) return res.status(500).json({ message: "Failed to submit rating" });
        res.json({ message: "Rating submitted successfully" });
      });
    }
  });
});

app.get("/storeaveragerating", authorizeRole(["systemadmin", "normaluser", "storeowner"]), (req, res) => {
  const query = `
    SELECT store.storeowner, store.storename, store.email, store.logo, store.address, AVG(store_ratings.rating) AS average_rating
    FROM store
    LEFT JOIN store_ratings ON store.storename = store_ratings.storename
    GROUP BY store.storename, store.address
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(400).json({ message: "Error while fetching store average ratings" });
    res.json(rows);
  });
});

// Start server
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
