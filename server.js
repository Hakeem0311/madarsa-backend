const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "MADARSA_FAIZ_SECRET_KEY"; // change later

// Database
const db = new sqlite3.Database("./madarsa.db");

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    father TEXT,
    aadhar TEXT,
    dob TEXT,
    class TEXT,
    phone TEXT,
    hifz TEXT,
    qualified INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    phone TEXT,
    salary TEXT
  )`);
});

// Create default admin
db.get("SELECT * FROM admins WHERE username = 'admin'", async (err, row) => {
  if (!row) {
    const hash = await bcrypt.hash("Faiz@786", 10);
    db.run("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ["admin", hash]);
    console.log("Default admin created: admin / Faiz@786");
  }
});

// Login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM admins WHERE username = ?", [username], async (err, admin) => {
    if (!admin) return res.status(401).json({ error: "Invalid login" });

    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid login" });

    const token = jwt.sign({ id: admin.id }, SECRET, { expiresIn: "1d" });
    res.json({ token });
  });
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.sendStatus(401);

  const token = header.split(" ")[1];
  try {
    jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// Test protected route
app.get("/api/students", auth, (req, res) => {
  db.all("SELECT * FROM students", [], (err, rows) => {
    res.json(rows);
  });
});

// ======================
// STUDENTS CRUD (Protected)
// ======================

// Get all students
app.get("/api/students", auth, (req, res) => {
  db.all("SELECT * FROM students", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add student
app.post("/api/students", auth, (req, res) => {
  const { name, father, aadhar, dob, studentClass, phone, hifz } = req.body;
  db.run(
    `INSERT INTO students (name, father, aadhar, dob, class, phone, hifz, qualified)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
    [name, father, aadhar, dob, studentClass, phone, hifz],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// Update student
app.put("/api/students/:id", auth, (req, res) => {
  const id = req.params.id;
  const { name, father, aadhar, dob, studentClass, phone, hifz, qualified } = req.body;

  db.run(
    `UPDATE students
     SET name=?, father=?, aadhar=?, dob=?, class=?, phone=?, hifz=?, qualified=?
     WHERE id=?`,
    [name, father, aadhar, dob, studentClass, phone, hifz, qualified ? 1 : 0, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    }
  );
});

// Delete student
app.delete("/api/students/:id", auth, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM students WHERE id=?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// ======================
// TEACHERS CRUD (Protected)
// ======================

// Get all teachers
app.get("/api/teachers", auth, (req, res) => {
  db.all("SELECT * FROM teachers", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add teacher
app.post("/api/teachers", auth, (req, res) => {
  const { name, phone, salary } = req.body;
  db.run(
    `INSERT INTO teachers (name, phone, salary) VALUES (?, ?, ?)`,
    [name, phone, salary],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// Update teacher
app.put("/api/teachers/:id", auth, (req, res) => {
  const id = req.params.id;
  const { name, phone, salary } = req.body;

  db.run(
    `UPDATE teachers SET name=?, phone=?, salary=? WHERE id=?`,
    [name, phone, salary, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    }
  );
});

// Delete teacher
app.delete("/api/teachers/:id", auth, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM teachers WHERE id=?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// ======================
// CHANGE PASSWORD (Protected)
// ======================

app.post("/api/change-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  // Get current admin (only one admin assumed)
  db.get("SELECT * FROM admins WHERE id = 1", async (err, admin) => {
    if (err || !admin) {
      return res.status(500).json({ error: "Admin not found" });
    }

    const ok = await bcrypt.compare(oldPassword, admin.password_hash);
    if (!ok) {
      return res.status(400).json({ error: "Old password is incorrect" });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    db.run(
      "UPDATE admins SET password_hash = ? WHERE id = 1",
      [newHash],
      function (err2) {
        if (err2) return res.status(500).json({ error: "Failed to update password" });
        res.json({ success: true });
      }
    );
  });
});


// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

